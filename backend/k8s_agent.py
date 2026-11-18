#!/usr/bin/env python3
"""SM-Watch Kubernetes agent.

Runs inside a cluster with a strictly READ-ONLY ServiceAccount (no Secrets, no exec, no writes except patching its own
token Secret). It only makes OUTBOUND connections: every 30 s it reports a small summary to the control plane, and it
answers on-demand questions (list pods, read logs, ...) that the dashboard queues for it. Nothing is stored.

Standard library only.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import json
import logging
import os
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

AGENT_VERSION = "1.3.0"
SMWATCH_URL = os.getenv("SMWATCH_URL", "").rstrip("/")
_TOKEN = os.getenv("SMWATCH_TOKEN", "")                       # this cluster's agent token (from the Secret the manifest created)
AGENT_ALLOW_INSECURE = os.getenv("AGENT_ALLOW_INSECURE", "") == "1"
K8S_API = os.getenv("K8S_API", "https://kubernetes.default.svc").rstrip("/")
SA_DIR = os.getenv("K8S_SA_DIR", "/var/run/secrets/kubernetes.io/serviceaccount")
TOKEN_FILE = os.getenv("K8S_TOKEN_FILE", f"{SA_DIR}/token")
CA_FILE = os.getenv("K8S_CA_FILE", f"{SA_DIR}/ca.crt")
NAMESPACE_FILE = os.getenv("K8S_NAMESPACE_FILE", f"{SA_DIR}/namespace")
SECRET_NAME = os.getenv("SMWATCH_SECRET", "smwatch-agent")
REPORT_INTERVAL = max(10, int(os.getenv("SMWATCH_REPORT_INTERVAL", "30")))
MAX_OUTPUT = 800_000
MAX_LIST_ITEMS = 10_000

log = logging.getLogger("sm-watch-k8s-agent")

NAME_RE = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$")
NS_RE = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
LABEL_RE = re.compile(r"^[A-Za-z0-9]([-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?$")


# ----------------------------------------------------------------------------------------------- Kubernetes API (read-only)
class K8sError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(f"Kubernetes API {status}: {message}")
        self.status = status


def _read(path: str) -> str:
    with open(path) as handle:
        return handle.read().strip()


_ssl_context: ssl.SSLContext | None = None


def _context() -> ssl.SSLContext:
    global _ssl_context
    if _ssl_context is None:
        _ssl_context = ssl.create_default_context(cafile=CA_FILE if os.path.exists(CA_FILE) else None)
    return _ssl_context


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """The agent never follows HTTP redirects. urllib would re-send the Authorization header (this agent's token) to wherever a
    redirect points, including another host or plain http: a misconfigured or hostile proxy could collect tokens that way."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, f"refused to follow a redirect to {newurl} (credentials are never forwarded)", headers, fp)


_k8s_opener = None
_control_opener = urllib.request.build_opener(_NoRedirect)


def _k8s_open(request, timeout: float):
    global _k8s_opener
    if _k8s_opener is None:
        _k8s_opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=_context()))
    return _k8s_opener.open(request, timeout=timeout)


def kapi(path: str, params: dict | None = None, *, method: str = "GET", body: bytes | None = None, content_type: str | None = None,
         timeout: float = 20, raw: bool = False, max_bytes: int = 30_000_000):
    """One call to the Kubernetes API with the pod's own ServiceAccount token (re-read each time: it is rotated by the kubelet)."""
    url = K8S_API + path + (("?" + urllib.parse.urlencode(params)) if params else "")
    headers = {"Authorization": f"Bearer {_read(TOKEN_FILE)}", "Accept": "application/json, */*" if raw else "application/json", "User-Agent": f"sm-watch-k8s-agent/{AGENT_VERSION}"}
    if content_type:
        headers["Content-Type"] = content_type
    request = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with _k8s_open(request, timeout) as response:
            data = response.read(max_bytes + 1)
    except urllib.error.HTTPError as error:
        detail = error.read(2000).decode(errors="replace")
        try:
            detail = json.loads(detail).get("message", detail)
        except ValueError:
            pass
        raise K8sError(error.code, detail[:300]) from None
    if len(data) > max_bytes:
        raise K8sError(413, "response too large")
    return data.decode(errors="replace") if raw else json.loads(data.decode() or "{}")


def klist(path: str, params: dict | None = None, cap: int = MAX_LIST_ITEMS) -> tuple[list[dict], bool]:
    """Follows Kubernetes pagination. Returns (items, truncated)."""
    items: list[dict] = []
    token = None
    while True:
        query = dict(params or {})
        query["limit"] = min(500, cap - len(items))
        if token:
            query["continue"] = token
        data = kapi(path, query)
        items.extend(data.get("items") or [])
        token = (data.get("metadata") or {}).get("continue")
        if not token or len(items) >= cap:
            return items, bool(token)


# ----------------------------------------------------------------------------------------------- quantities and formatting
_SUFFIX = {"n": 1e-9, "u": 1e-6, "m": 1e-3, "": 1.0, "k": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "P": 1e15, "E": 1e18,
           "Ki": 1024.0, "Mi": 1024.0**2, "Gi": 1024.0**3, "Ti": 1024.0**4, "Pi": 1024.0**5, "Ei": 1024.0**6}
_QUANTITY = re.compile(r"^([0-9]*\.?[0-9]+(?:[eE][+-]?[0-9]+)?)([a-zA-Z]*)$")


def quantity(value) -> float:
    match = _QUANTITY.match(str(value or "0").strip())
    if not match or match.group(2) not in _SUFFIX:
        return 0.0
    return float(match.group(1)) * _SUFFIX[match.group(2)]


def cpu_m(value) -> float:
    return round(quantity(value) * 1000, 1)


def mem_mib(value) -> float:
    return round(quantity(value) / 1024**2, 1)


def meta(obj: dict) -> dict:
    return obj.get("metadata") or {}


def created(obj: dict) -> str | None:
    return meta(obj).get("creationTimestamp")


def owner(obj: dict) -> str:
    refs = meta(obj).get("ownerReferences") or []
    return f"{refs[0].get('kind', '')}/{refs[0].get('name', '')}" if refs else ""


def pod_status(pod: dict) -> str:
    """The status column `kubectl get pods` shows (CrashLoopBackOff, ImagePullBackOff, Terminating, ...)."""
    status = pod.get("status") or {}
    reason = status.get("reason") or status.get("phase") or "Unknown"
    init_specs = (pod.get("spec") or {}).get("initContainers") or []
    for index, cs in enumerate(status.get("initContainerStatuses") or []):
        state = cs.get("state") or {}
        terminated, waiting = state.get("terminated"), state.get("waiting")
        if terminated and terminated.get("exitCode") == 0:
            continue
        if terminated:
            return "Init:" + (terminated.get("reason") or f"ExitCode:{terminated.get('exitCode')}")
        if waiting and waiting.get("reason") not in (None, "PodInitializing"):
            return "Init:" + waiting["reason"]
        return f"Init:{index}/{len(init_specs)}"
    has_running = False
    for cs in reversed(status.get("containerStatuses") or []):
        state = cs.get("state") or {}
        if (state.get("waiting") or {}).get("reason"):
            reason = state["waiting"]["reason"]
        elif (state.get("terminated") or {}).get("reason"):
            reason = state["terminated"]["reason"]
        elif state.get("terminated"):
            reason = f"ExitCode:{state['terminated'].get('exitCode')}"
        elif state.get("running") and cs.get("ready"):
            has_running = True
    if reason == "Completed" and has_running:
        reason = "Running"
    if meta(pod).get("deletionTimestamp"):
        reason = "Unknown" if status.get("reason") == "NodeLost" else "Terminating"
    return reason


def container_state(cs: dict) -> tuple[str, str]:
    state = cs.get("state") or {}
    for name in ("running", "waiting", "terminated"):
        if name in state:
            return name, (state[name] or {}).get("reason") or ""
    return "unknown", ""


def pod_row(pod: dict) -> dict:
    spec, status = pod.get("spec") or {}, pod.get("status") or {}
    statuses = {c["name"]: c for c in status.get("containerStatuses") or []}
    containers = []
    req_cpu = req_mem = lim_cpu = lim_mem = 0.0
    for c in spec.get("containers") or []:
        cs = statuses.get(c["name"], {})
        state, why = container_state(cs)
        resources = c.get("resources") or {}
        req, lim = resources.get("requests") or {}, resources.get("limits") or {}
        req_cpu += cpu_m(req.get("cpu")); req_mem += mem_mib(req.get("memory")); lim_cpu += cpu_m(lim.get("cpu")); lim_mem += mem_mib(lim.get("memory"))
        containers.append({"name": c["name"], "image": c.get("image", ""), "ready": bool(cs.get("ready")), "restarts": cs.get("restartCount", 0), "state": state, "reason": why})
    ready = sum(1 for c in containers if c["ready"])
    return {
        "ns": meta(pod).get("namespace", ""), "name": meta(pod).get("name", ""), "phase": status.get("phase", ""), "status": pod_status(pod),
        "ready": f"{ready}/{len(containers)}", "restarts": sum(c["restarts"] for c in containers), "node": spec.get("nodeName", ""), "ip": status.get("podIP", ""),
        "created": created(pod), "owner": owner(pod), "qos": status.get("qosClass", ""), "containers": containers,
        "cpu_req_m": round(req_cpu, 1), "mem_req_mib": round(req_mem, 1), "cpu_lim_m": round(lim_cpu, 1), "mem_lim_mib": round(lim_mem, 1),
    }


def node_row(node: dict) -> dict:
    status = node.get("status") or {}
    conditions = {c["type"]: c for c in status.get("conditions") or []}
    capacity, alloc, info = status.get("capacity") or {}, status.get("allocatable") or {}, status.get("nodeInfo") or {}
    labels = meta(node).get("labels") or {}
    addresses = {a["type"]: a["address"] for a in status.get("addresses") or []}
    return {
        "name": meta(node).get("name", ""), "ready": (conditions.get("Ready") or {}).get("status") == "True",
        "roles": sorted(k.split("/", 1)[1] for k in labels if k.startswith("node-role.kubernetes.io/")) or ["worker"],
        "version": info.get("kubeletVersion", ""), "os": info.get("osImage", ""), "kernel": info.get("kernelVersion", ""), "runtime": info.get("containerRuntimeVersion", ""),
        "arch": info.get("architecture", ""), "ip": addresses.get("InternalIP", ""), "created": created(node), "unschedulable": bool((node.get("spec") or {}).get("unschedulable")),
        "taints": len((node.get("spec") or {}).get("taints") or []),
        "cpu_cap_m": cpu_m(capacity.get("cpu")), "mem_cap_mib": mem_mib(capacity.get("memory")), "pods_cap": int(quantity(capacity.get("pods"))),
        "cpu_alloc_m": cpu_m(alloc.get("cpu")), "mem_alloc_mib": mem_mib(alloc.get("memory")),
        "conditions": [{"type": t, "status": c.get("status"), "reason": c.get("reason", ""), "message": (c.get("message") or "")[:200]} for t, c in conditions.items()],
    }


def images(template: dict) -> list[str]:
    return [c.get("image", "") for c in ((template.get("spec") or {}).get("containers") or [])]


def deployment_row(d: dict) -> dict:
    spec, status = d.get("spec") or {}, d.get("status") or {}
    conditions = {c["type"]: c for c in status.get("conditions") or []}
    return {"ns": meta(d)["namespace"], "name": meta(d)["name"], "desired": spec.get("replicas", 1), "ready": status.get("readyReplicas", 0), "updated": status.get("updatedReplicas", 0),
            "available": status.get("availableReplicas", 0), "images": images(spec.get("template") or {}), "strategy": (spec.get("strategy") or {}).get("type", ""),
            "created": created(d), "message": (conditions.get("Available") or {}).get("message", "")[:200] if (conditions.get("Available") or {}).get("status") != "True" else ""}


def statefulset_row(s: dict) -> dict:
    spec, status = s.get("spec") or {}, s.get("status") or {}
    return {"ns": meta(s)["namespace"], "name": meta(s)["name"], "desired": spec.get("replicas", 1), "ready": status.get("readyReplicas", 0), "updated": status.get("updatedReplicas", 0),
            "available": status.get("availableReplicas", status.get("readyReplicas", 0)), "images": images(spec.get("template") or {}), "strategy": (spec.get("updateStrategy") or {}).get("type", ""),
            "created": created(s), "message": ""}


def daemonset_row(d: dict) -> dict:
    status = d.get("status") or {}
    return {"ns": meta(d)["namespace"], "name": meta(d)["name"], "desired": status.get("desiredNumberScheduled", 0), "ready": status.get("numberReady", 0),
            "updated": status.get("updatedNumberScheduled", 0), "available": status.get("numberAvailable", 0), "images": images((d.get("spec") or {}).get("template") or {}),
            "strategy": ((d.get("spec") or {}).get("updateStrategy") or {}).get("type", ""), "created": created(d), "message": ""}


def job_row(j: dict) -> dict:
    spec, status = j.get("spec") or {}, j.get("status") or {}
    conditions = {c["type"]: c.get("status") for c in status.get("conditions") or []}
    state = "Complete" if conditions.get("Complete") == "True" else "Failed" if conditions.get("Failed") == "True" else "Running" if status.get("active") else "Pending"
    return {"ns": meta(j)["namespace"], "name": meta(j)["name"], "completions": spec.get("completions"), "succeeded": status.get("succeeded", 0), "failed": status.get("failed", 0),
            "active": status.get("active", 0), "state": state, "started": status.get("startTime"), "finished": status.get("completionTime"), "created": created(j), "owner": owner(j)}


def cronjob_row(c: dict) -> dict:
    spec, status = c.get("spec") or {}, c.get("status") or {}
    return {"ns": meta(c)["namespace"], "name": meta(c)["name"], "schedule": spec.get("schedule", ""), "suspend": bool(spec.get("suspend")), "last": status.get("lastScheduleTime"),
            "last_success": status.get("lastSuccessfulTime"), "active": len(status.get("active") or []), "created": created(c)}


def service_row(s: dict) -> dict:
    spec, status = s.get("spec") or {}, s.get("status") or {}
    ingress = (status.get("loadBalancer") or {}).get("ingress") or []
    return {"ns": meta(s)["namespace"], "name": meta(s)["name"], "type": spec.get("type", "ClusterIP"), "cluster_ip": spec.get("clusterIP", ""),
            "external": [i.get("ip") or i.get("hostname") or "" for i in ingress] + list(spec.get("externalIPs") or []),
            "ports": [f"{p.get('port')}{('→' + str(p.get('targetPort'))) if p.get('targetPort') not in (None, p.get('port')) else ''}/{p.get('protocol', 'TCP')}" + (f" (node {p['nodePort']})" if p.get("nodePort") else "") for p in spec.get("ports") or []],
            "selector": spec.get("selector") or {}, "created": created(s)}


def ingress_row(i: dict) -> dict:
    spec, status = i.get("spec") or {}, i.get("status") or {}
    return {"ns": meta(i)["namespace"], "name": meta(i)["name"], "class": spec.get("ingressClassName") or (meta(i).get("annotations") or {}).get("kubernetes.io/ingress.class", ""),
            "hosts": [r.get("host", "*") for r in spec.get("rules") or []], "address": [a.get("ip") or a.get("hostname") or "" for a in (status.get("loadBalancer") or {}).get("ingress") or []],
            "tls": len(spec.get("tls") or []), "created": created(i)}


def hpa_row(h: dict) -> dict:
    spec, status = h.get("spec") or {}, h.get("status") or {}
    current = {}
    for m in status.get("currentMetrics") or []:
        resource = m.get("resource") or {}
        name = resource.get("name") or m.get("type")
        value = (resource.get("current") or {})
        current[name] = f"{value['averageUtilization']}%" if "averageUtilization" in value else value.get("averageValue", "")
    metrics = []
    for m in spec.get("metrics") or []:
        resource = m.get("resource") or {}
        name = resource.get("name") or m.get("type")
        target = resource.get("target") or {}
        wanted = f"{target['averageUtilization']}%" if "averageUtilization" in target else target.get("averageValue") or target.get("value") or ""
        metrics.append({"type": m.get("type", ""), "name": name, "target": wanted, "current": current.get(name, "unknown")})
    ref = spec.get("scaleTargetRef") or {}
    return {"ns": meta(h)["namespace"], "name": meta(h)["name"], "target": f"{ref.get('kind', '')}/{ref.get('name', '')}", "min": spec.get("minReplicas", 1), "max": spec.get("maxReplicas", 0),
            "current": status.get("currentReplicas", 0), "desired": status.get("desiredReplicas", 0), "metrics": metrics, "last_scale": status.get("lastScaleTime"),
            "conditions": [{"type": c.get("type"), "status": c.get("status"), "reason": c.get("reason", ""), "message": (c.get("message") or "")[:200]} for c in status.get("conditions") or []],
            "created": created(h)}


def event_row(e: dict) -> dict:
    obj = e.get("involvedObject") or {}
    return {"ns": meta(e).get("namespace", ""), "type": e.get("type", ""), "reason": e.get("reason", ""), "object": f"{obj.get('kind', '')}/{obj.get('name', '')}",
            "message": (e.get("message") or "")[:500], "count": e.get("count") or (e.get("series") or {}).get("count") or 1,
            "last": e.get("lastTimestamp") or e.get("eventTime") or (e.get("series") or {}).get("lastObservedTime") or meta(e).get("creationTimestamp"),
            "component": (e.get("source") or {}).get("component") or e.get("reportingComponent", "")}


def pvc_row(p: dict) -> dict:
    spec, status = p.get("spec") or {}, p.get("status") or {}
    return {"ns": meta(p)["namespace"], "name": meta(p)["name"], "status": status.get("phase", ""), "volume": spec.get("volumeName", ""),
            "capacity": (status.get("capacity") or {}).get("storage", ""), "class": spec.get("storageClassName", ""), "modes": status.get("accessModes") or [], "created": created(p)}


def quota_row(q: dict) -> dict:
    status = q.get("status") or {}
    return {"ns": meta(q)["namespace"], "name": meta(q)["name"], "resources": [{"name": k, "hard": v, "used": (status.get("used") or {}).get(k, "0")} for k, v in (status.get("hard") or {}).items()]}


# ----------------------------------------------------------------------------------------------- what the dashboard may ask for
# A fixed table: kind -> (API path template, row formatter). There is no way to reach any other path.
def _path(group: str, plural: str, namespace: str) -> str:
    base = f"/apis/{group}" if group.count("/") else ("/api/v1" if not group else f"/apis/{group}")
    return f"{base}/namespaces/{namespace}/{plural}" if namespace else f"{base}/{plural}"


LISTS = {
    "pods": ("v1", "pods", pod_row), "deployments": ("apps/v1", "deployments", deployment_row), "statefulsets": ("apps/v1", "statefulsets", statefulset_row),
    "daemonsets": ("apps/v1", "daemonsets", daemonset_row), "jobs": ("batch/v1", "jobs", job_row), "cronjobs": ("batch/v1", "cronjobs", cronjob_row),
    "services": ("v1", "services", service_row), "ingresses": ("networking.k8s.io/v1", "ingresses", ingress_row), "hpa": ("autoscaling/v2", "horizontalpodautoscalers", hpa_row),
    "pvcs": ("v1", "persistentvolumeclaims", pvc_row), "quotas": ("v1", "resourcequotas", quota_row), "events": ("v1", "events", event_row),
}
DESCRIBE = {"pod": ("v1", "pods", True), "deployment": ("apps/v1", "deployments", True), "statefulset": ("apps/v1", "statefulsets", True), "daemonset": ("apps/v1", "daemonsets", True),
            "job": ("batch/v1", "jobs", True), "cronjob": ("batch/v1", "cronjobs", True), "service": ("v1", "services", True), "ingress": ("networking.k8s.io/v1", "ingresses", True),
            "hpa": ("autoscaling/v2", "horizontalpodautoscalers", True), "pvc": ("v1", "persistentvolumeclaims", True), "node": ("v1", "nodes", False), "namespace": ("v1", "namespaces", False)}


def api_path(group_version: str, plural: str, namespace: str = "", name: str = "") -> str:
    base = "/api/v1" if group_version == "v1" else f"/apis/{group_version}"
    path = f"{base}/namespaces/{urllib.parse.quote(namespace)}/{plural}" if namespace else f"{base}/{plural}"
    return f"{path}/{urllib.parse.quote(name)}" if name else path


def redact(obj):
    """Describe output must never carry secrets: env values, last-applied manifests and managedFields are removed."""
    if isinstance(obj, dict):
        out = {}
        for key, value in obj.items():
            if key == "managedFields":
                continue
            if key == "annotations" and isinstance(value, dict):
                value = {k: v for k, v in value.items() if k != "kubectl.kubernetes.io/last-applied-configuration"}
            if key == "env" and isinstance(value, list):
                value = [({**e, "value": "<redacted>"} if isinstance(e, dict) and "value" in e else e) for e in value]
            out[key] = redact(value)
        return out
    if isinstance(obj, list):
        return [redact(item) for item in obj]
    return obj


def check(task: dict) -> None:
    for field, rx in (("namespace", NS_RE), ("name", NAME_RE), ("container", LABEL_RE)):
        value = task.get(field) or ""
        if value and not rx.match(value):
            raise ValueError(f"Invalid {field}")


def matches(name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(name, p) for p in patterns)


_policy: dict | None = None            # {"enabled": bool, "include": [...], "exclude": [...]} over namespaces, for logs


def logs_allowed(namespace: str) -> bool:
    if _policy is None:
        return True
    return bool(_policy.get("enabled")) and matches(namespace, _policy.get("include") or []) and not matches(namespace, _policy.get("exclude") or [])


def apply_policy(candidate) -> None:
    global _policy
    try:
        if isinstance(candidate, dict) and isinstance(candidate["enabled"], bool) and all(isinstance(x, str) for x in candidate["include"] + candidate["exclude"]):
            _policy = candidate
    except (KeyError, TypeError):
        pass


def _selector_string(selector: dict | None) -> str | None:
    """A labelSelector query string from a Kubernetes selector (matchLabels plus In / NotIn / Exists / DoesNotExist), or None
    when it selects nothing."""
    if not selector:
        return None
    labels = selector.get("matchLabels") if "matchLabels" in selector or "matchExpressions" in selector else selector
    parts = [f"{k}={v}" for k, v in (labels or {}).items()]
    for expr in selector.get("matchExpressions") or [] if isinstance(selector.get("matchExpressions"), list) else []:
        key, op, values = expr.get("key", ""), expr.get("operator", ""), expr.get("values") or []
        if op == "In":
            parts.append(f"{key} in ({','.join(values)})")
        elif op == "NotIn":
            parts.append(f"{key} notin ({','.join(values)})")
        elif op == "Exists":
            parts.append(key)
        elif op == "DoesNotExist":
            parts.append(f"!{key}")
    return ",".join(parts) or None


def _events_for(namespace: str, names: list[str], cap: int = 60) -> list[dict]:
    """Events about any of `names` in `namespace`, newest first (one list call, filtered here)."""
    if not names:
        return []
    wanted = set(names)
    events, _ = klist(api_path("v1", "events", namespace), cap=2000)
    rows = [event_row(e) for e in events if (e.get("involvedObject") or {}).get("name") in wanted]
    rows.sort(key=lambda r: r.get("last") or "", reverse=True)
    return rows[:cap]


def related(resource: str, namespace: str, name: str) -> dict:
    """One object with everything connected to it: its pods, the services that select it, its owner chain, the volumes it
    mounts, the node it runs on, and the events of the object and its pods. Same read-only permissions as `describe`."""
    gv, plural, namespaced = DESCRIBE[resource]
    obj = kapi(api_path(gv, plural, namespace if namespaced else "", name))
    spec = obj.get("spec") or {}
    links: list[dict] = []
    pods: list[dict] = []
    selector = None
    if resource in ("deployment", "statefulset", "daemonset", "job", "replicaset"):
        selector = _selector_string(spec.get("selector"))
    elif resource == "service":
        selector = _selector_string(spec.get("selector") or None)
    elif resource == "cronjob":
        jobs, _ = klist(api_path("batch/v1", "jobs", namespace), cap=500)
        mine = [meta(j)["name"] for j in jobs if any(r.get("kind") == "CronJob" and r.get("name") == name for r in meta(j).get("ownerReferences") or [])]
        links += [{"kind": "Job", "name": j, "ns": namespace} for j in mine[-20:]]
        if mine:
            selector = f"job-name in ({','.join(mine[-20:])})"
    if resource == "pod":
        pods = [pod_row(obj)]
        for ref in meta(obj).get("ownerReferences") or []:
            links.append({"kind": ref.get("kind", ""), "name": ref.get("name", ""), "ns": namespace, "relation": "owner"})
            if ref.get("kind") == "ReplicaSet":                       # ReplicaSet -> Deployment
                try:
                    rs = kapi(api_path("apps/v1", "replicasets", namespace, ref.get("name", "")))
                    links += [{"kind": r.get("kind", ""), "name": r.get("name", ""), "ns": namespace, "relation": "owner"} for r in meta(rs).get("ownerReferences") or []]
                except K8sError:
                    pass
        for volume in spec.get("volumes") or []:
            claim = (volume.get("persistentVolumeClaim") or {}).get("claimName")
            if claim:
                links.append({"kind": "PersistentVolumeClaim", "name": claim, "ns": namespace, "relation": "volume"})
        if spec.get("nodeName"):
            links.append({"kind": "Node", "name": spec["nodeName"], "ns": "", "relation": "runs on"})
    elif selector:
        items, _ = klist(api_path("v1", "pods", namespace), {"labelSelector": selector}, cap=300)
        pods = [pod_row(p) for p in items]
    if resource == "pvc":
        items, _ = klist(api_path("v1", "pods", namespace), cap=MAX_LIST_ITEMS)
        pods = [pod_row(p) for p in items if any((v.get("persistentVolumeClaim") or {}).get("claimName") == name for v in (p.get("spec") or {}).get("volumes") or [])]
    if resource == "ingress":
        for rule in spec.get("rules") or []:
            for path in ((rule.get("http") or {}).get("paths") or []):
                svc = (((path.get("backend") or {}).get("service")) or {}).get("name")
                if svc:
                    links.append({"kind": "Service", "name": svc, "ns": namespace, "relation": f"{rule.get('host', '*')}{path.get('path', '/')}"})
    if resource == "hpa":
        ref = spec.get("scaleTargetRef") or {}
        links.append({"kind": ref.get("kind", ""), "name": ref.get("name", ""), "ns": namespace, "relation": "scales"})
    # services that send traffic to these pods (or to this pod)
    services: list[dict] = []
    if namespaced and resource not in ("service", "namespace") and (pods or resource == "pod"):
        pod_labels = [meta(p).get("labels") or {} for p in ([obj] if resource == "pod" else klist(api_path("v1", "pods", namespace), {"labelSelector": selector}, cap=50)[0] if selector else [])]
        all_services, _ = klist(api_path("v1", "services", namespace), cap=500)
        for svc in all_services:
            sel = (svc.get("spec") or {}).get("selector") or {}
            if sel and any(all(labels.get(k) == v for k, v in sel.items()) for labels in pod_labels):
                services.append(service_row(svc))
    names = [name] + [p["name"] for p in pods[:100]]
    events = _events_for(namespace, names) if namespaced else rows_for_cluster_object(name)
    return {"object": redact(obj), "pods": pods, "services": services, "links": links, "events": events, "selector": selector or ""}


def rows_for_cluster_object(name: str) -> list[dict]:
    events, _ = klist(api_path("v1", "events", ""), {"fieldSelector": f"involvedObject.name={name}"}, cap=100)
    return sorted((event_row(e) for e in events), key=lambda r: r.get("last") or "", reverse=True)[:60]


def run_query(task: dict) -> tuple[str, bool]:
    """Executes one validated question. Returns (output, truncated). Output is JSON, except for logs (plain text)."""
    check(task)
    kind, namespace, name = task.get("kind", ""), task.get("namespace") or "", task.get("name") or ""
    limit = max(1, min(500, int(task.get("limit") or 200)))
    if kind == "namespaces":
        items, truncated = klist("/api/v1/namespaces")
        pods, _ = klist("/api/v1/pods", cap=MAX_LIST_ITEMS)
        counts: dict[str, list[int]] = {}
        for pod in pods:
            row = counts.setdefault(meta(pod).get("namespace", ""), [0, 0])
            row[1] += 1
            row[0] += 1 if (pod.get("status") or {}).get("phase") == "Running" else 0
        rows = [{"name": meta(n)["name"], "status": (n.get("status") or {}).get("phase", ""), "created": created(n), "pods_running": counts.get(meta(n)["name"], [0, 0])[0],
                 "pods_total": counts.get(meta(n)["name"], [0, 0])[1], "labels": len(meta(n).get("labels") or {})} for n in items]
        return _json({"items": rows, "truncated": truncated})
    if kind == "nodes":
        items, truncated = klist("/api/v1/nodes", cap=1000)
        return _json({"items": [node_row(n) for n in items], "truncated": truncated})
    if kind in LISTS:
        gv, plural, formatter = LISTS[kind]
        params = {}
        if kind == "events":
            params["fieldSelector"] = "type=Warning" if task.get("warnings_only") else ""
            params = {k: v for k, v in params.items() if v}
        items, truncated = klist(api_path(gv, plural, namespace), params, cap=limit if kind != "events" else min(limit, 500))
        rows = [formatter(i) for i in items]
        if kind == "events":
            rows.sort(key=lambda r: r.get("last") or "", reverse=True)
        return _json({"items": rows[:limit], "truncated": truncated or len(rows) > limit})
    if kind in ("pod_metrics", "node_metrics"):
        try:
            if kind == "node_metrics":
                items, _ = klist("/apis/metrics.k8s.io/v1beta1/nodes", cap=1000)
                rows = [{"name": meta(i)["name"], "cpu_m": cpu_m((i.get("usage") or {}).get("cpu")), "mem_mib": mem_mib((i.get("usage") or {}).get("memory"))} for i in items]
            else:
                items, _ = klist(api_path("metrics.k8s.io/v1beta1", "pods", namespace), cap=MAX_LIST_ITEMS)
                rows = [{"ns": meta(i).get("namespace", ""), "name": meta(i)["name"], "cpu_m": round(sum(cpu_m((c.get("usage") or {}).get("cpu")) for c in i.get("containers") or []), 1),
                         "mem_mib": round(sum(mem_mib((c.get("usage") or {}).get("memory")) for c in i.get("containers") or []), 1),
                         "containers": [{"name": c["name"], "cpu_m": cpu_m((c.get("usage") or {}).get("cpu")), "mem_mib": mem_mib((c.get("usage") or {}).get("memory"))} for c in i.get("containers") or []]} for i in items]
            return _json({"items": rows, "truncated": False, "available": True})
        except K8sError as error:
            if error.status in (404, 503):
                return _json({"items": [], "truncated": False, "available": False, "reason": "metrics-server is not installed or not ready in this cluster"})
            raise
    if kind == "describe":
        resource = task.get("resource", "")
        if resource not in DESCRIBE or not name:
            raise ValueError("Unknown resource")
        gv, plural, namespaced = DESCRIBE[resource]
        if namespaced and not namespace:
            raise ValueError("namespace is required")
        obj = kapi(api_path(gv, plural, namespace if namespaced else "", name))
        selector = f"involvedObject.name={name}" + (f",involvedObject.namespace={namespace}" if namespaced else "")
        events, _ = klist(api_path("v1", "events", namespace if namespaced else "default" if resource == "node" else ""), {"fieldSelector": selector}, cap=100) if True else ([], False)
        rows = sorted((event_row(e) for e in events), key=lambda r: r.get("last") or "", reverse=True)
        return _json({"object": redact(obj), "events": rows[:50]})
    if kind == "related":
        resource = task.get("resource", "")
        if resource not in DESCRIBE or not name:
            raise ValueError("Unknown resource")
        if DESCRIBE[resource][2] and not namespace:
            raise ValueError("namespace is required")
        return _json(related(resource, namespace, name))
    if kind == "logs":
        if not namespace or not name:
            raise ValueError("namespace and pod are required")
        if not logs_allowed(namespace):
            raise ValueError("Blocked by this cluster's log access policy")
        params = {"tailLines": str(max(1, min(2000, int(task.get("lines") or 200)))) if not task.get("grep") else "20000", "timestamps": "true"}
        if task.get("container"):
            params["container"] = task["container"]
        window = max(int(task.get("since_seconds") or 0), int(task.get("since_minutes") or 0) * 60)
        if window > 0:
            params["sinceSeconds"] = str(min(window, 31 * 86400))
        if task.get("previous"):
            params["previous"] = "true"
        text = kapi(api_path("v1", "pods", namespace, name) + "/log", params, raw=True, max_bytes=40_000_000, timeout=30)
        rows = [r for r in text.splitlines() if r.strip()]
        needle = (task.get("grep") or "").lower()
        if needle:
            rows = [r for r in rows if needle in r.lower()]
        rows = rows[-max(1, min(2000, int(task.get("lines") or 200))):]
        output = "\n".join(rows)
        truncated = len(output.encode()) > MAX_OUTPUT
        return (output.encode()[-MAX_OUTPUT:].decode(errors="replace") if truncated else output), truncated
    raise ValueError("Unknown query kind")


def _json(value) -> tuple[str, bool]:
    text = json.dumps(value, separators=(",", ":"))
    if len(text.encode()) > MAX_OUTPUT:   # keep valid JSON: drop rows until it fits
        items = value.get("items", [])
        while items and len(json.dumps({**value, "items": items, "truncated": True}).encode()) > MAX_OUTPUT:
            items = items[: int(len(items) * 0.8)]
        text = json.dumps({**value, "items": items, "truncated": True}, separators=(",", ":"))
        return text, True
    return text, False


# ----------------------------------------------------------------------------------------------- the report
def usage_totals(nodes: list[dict]) -> dict:
    alloc_cpu = sum(cpu_m(((n.get("status") or {}).get("allocatable") or {}).get("cpu")) for n in nodes)
    alloc_mem = sum(mem_mib(((n.get("status") or {}).get("allocatable") or {}).get("memory")) for n in nodes)
    try:
        usage, _ = klist("/apis/metrics.k8s.io/v1beta1/nodes", cap=1000)
        return {"usage_available": True, "cpu_m": round(sum(cpu_m((u.get("usage") or {}).get("cpu")) for u in usage), 1), "mem_mib": round(sum(mem_mib((u.get("usage") or {}).get("memory")) for u in usage), 1),
                "cpu_alloc_m": round(alloc_cpu, 1), "mem_alloc_mib": round(alloc_mem, 1)}
    except K8sError:
        return {"usage_available": False, "cpu_m": None, "mem_mib": None, "cpu_alloc_m": round(alloc_cpu, 1), "mem_alloc_mib": round(alloc_mem, 1)}


# ----------------------------------------------------------------------------------------------- security checks
# Signs of a risky or compromised cluster, judged from object specs the agent already reads (no exec, no Secrets): privileged or
# host-level pods, mounts of the node's filesystem or container runtime socket, dangerous capabilities, crypto miners and reverse
# shells in container commands, images pulled from bare IP addresses, unowned pods hiding in kube-system, and RBAC bindings that
# give cluster-admin to workloads or anyone to anonymous users.
SYSTEM_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease", "kube-flannel", "calico-system", "calico-apiserver", "tigera-operator", "cilium", "cilium-system",
                     "longhorn-system", "metallb-system", "cert-manager", "ingress-nginx", "istio-system", "linkerd", "gatekeeper-system", "kyverno", "openebs", "rook-ceph",
                     "local-path-storage", "cattle-system", "cattle-fleet-system", "monitoring", "kube-prometheus-stack", "gke-managed-system", "gmp-system",
                     "amazon-cloudwatch", "aws-observability", "azure-arc", "smwatch"} | {n.strip() for n in os.getenv("SMWATCH_TRUSTED_NAMESPACES", "").split(",") if n.strip()}
SENSITIVE_HOST_PATHS = {"/": "critical", "/var/run/docker.sock": "critical", "/run/docker.sock": "critical", "/run/containerd/containerd.sock": "critical",
                        "/var/run/containerd/containerd.sock": "critical", "/var/run/crio/crio.sock": "critical", "/run/crio/crio.sock": "critical",
                        "/etc": "high", "/root": "high", "/home": "high", "/var/lib/kubelet": "high", "/etc/kubernetes": "high", "/proc": "high", "/sys": "high",
                        "/boot": "high", "/var/run": "high", "/run": "high", "/var/lib/docker": "high", "/var/lib/containerd": "high", "/dev": "high"}
RISKY_CAPS = {"SYS_ADMIN", "ALL", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "BPF", "SYS_RAWIO", "NET_ADMIN"}
MINER = re.compile(r"xmrig|xmr-stak|cpuminer|minerd|kdevtmpfsi|kinsing|ethminer|nbminer|t-rex|lolminer|phoenixminer|stratum\+(?:tcp|ssl)://|--donate-level|"
                   r"nicehash|minexmr|supportxmr|nanopool\.org|moneroocean|hashvault|c3pool|xmrpool|--coin[= ]monero", re.I)
REVERSE_SHELL = re.compile(r"/dev/(?:tcp|udp)/|\bbash -i\b.*[>&]|\bn(?:c|cat|etcat)\b.*\s-(?:e|c)\s|socat\b.*exec:|pty\.spawn\(|"
                           r"(?:curl|wget)\b[^|;]*\|\s*(?:ba|da|z)?sh\b|base64\s+(?:-d|--decode)[^|]*\|\s*(?:ba)?sh", re.I)
IP_REGISTRY = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?/")
SEVERITY_DOWN = {"critical": "high", "high": "low", "medium": "low", "low": "low"}
_rbac_cache: dict = {"at": 0.0, "findings": [], "checked": False, "error": None}


def workload_of(pod: dict) -> tuple[str, str]:
    """The controller a pod belongs to, as kubectl users name it: Deployment/web, not ReplicaSet/web-5d8f7c9b6 or the pod itself."""
    refs = meta(pod).get("ownerReferences") or []
    if not refs:
        return "Pod", meta(pod).get("name", "")
    kind, name = refs[0].get("kind", ""), refs[0].get("name", "")
    template_hash = (meta(pod).get("labels") or {}).get("pod-template-hash")
    if kind == "ReplicaSet" and template_hash and name.endswith("-" + template_hash):
        return "Deployment", name[: -len(template_hash) - 1]
    if kind == "Job" and re.search(r"-\d{8,}$", name):
        return "CronJob", re.sub(r"-\d{8,}$", "", name)
    return kind, name


def _container_findings(ns: str, workload: str, spec: dict, created_at: str | None, system: bool) -> list[dict]:
    out: list[dict] = []

    def add(rule: str, severity: str, title: str, detail: str, container: str = "", image: str = "", **evidence) -> None:
        if system and rule not in ("miner", "reverse_shell", "ip_registry"):
            severity, title, detail = SEVERITY_DOWN[severity], f"{title} (system namespace)", detail + " It runs in a system namespace, where this is common for cluster components: check that it is one you installed."
        out.append({"key": f"{rule}:{ns}/{workload}:{container}", "kind": f"k8s_{rule}", "severity": severity, "title": title[:200], "detail": detail[:1000], "namespace": ns,
                    "object": workload, "container": container, "image": image[:300], "created": created_at, **{k: str(v)[:300] for k, v in evidence.items() if v}})

    where = f"{workload} in namespace {ns}"
    if spec.get("hostPID"):
        add("host_pid", "high", f"{workload} shares the node's process namespace (hostPID)", f"{where} can see and signal every process on its node, including other containers.")
    if spec.get("hostIPC"):
        add("host_ipc", "high", f"{workload} shares the node's IPC namespace (hostIPC)", f"{where} can read shared memory of other processes on its node.")
    if spec.get("hostNetwork"):
        add("host_network", "medium", f"{workload} uses the node's network (hostNetwork)", f"{where} bypasses network policies and can listen on, or reach, any address of its node.")
    for volume in spec.get("volumes") or []:
        path = ((volume.get("hostPath") or {}).get("path") or "").rstrip("/") or ("/" if volume.get("hostPath") else "")
        if path in SENSITIVE_HOST_PATHS:
            runtime = path.endswith(".sock")
            add("host_path", SENSITIVE_HOST_PATHS[path], f"{workload} mounts {'the container runtime socket' if runtime else 'the node path ' + path}",
                f"{where} mounts {path} from its node" + (": whoever controls this pod controls every container on the node (and usually the node itself)." if runtime or path == "/" else ", which exposes the node's files to the container."),
                path=path)
    containers = [(c, "") for c in spec.get("containers") or []] + [(c, "init ") for c in spec.get("initContainers") or []] + [(c, "debug ") for c in spec.get("ephemeralContainers") or []]
    for c, role in containers:
        name, image = c.get("name", ""), c.get("image", "")
        sc = c.get("securityContext") or {}
        if sc.get("privileged"):
            add("privileged", "high", f"{workload}: {role}container {name} is privileged", f"Container {name} of {where} runs privileged: it has every capability and full access to the node's devices; escaping to the node is trivial.", name, image)
        caps = sorted({str(x).upper().removeprefix("CAP_") for x in ((sc.get("capabilities") or {}).get("add") or [])} & RISKY_CAPS)
        if caps:
            add("capabilities", "high", f"{workload}: {role}container {name} adds {', '.join(caps)}", f"Container {name} of {where} adds Linux capabilities ({', '.join(caps)}) that allow escaping the container or spying on the node.", name, image, capabilities=", ".join(caps))
        command = " ".join(str(x) for x in (c.get("command") or []) + (c.get("args") or []))[:2000]
        if MINER.search(image) or MINER.search(command):
            add("miner", "critical", f"Crypto miner in {workload}", f"Container {name} of {where} looks like a cryptocurrency miner (image or command matches known miners or mining pools). Unless you run it on purpose, the cluster is compromised: delete the workload, find how it was created (audit log) and rotate credentials.", name, image, command=command)
        if REVERSE_SHELL.search(command):
            add("reverse_shell", "critical", f"Suspicious command in {workload}", f"Container {name} of {where} starts with a reverse shell or downloads and runs a script. Check who created it.", name, image, command=command)
        if IP_REGISTRY.match(image):
            add("ip_registry", "medium", f"{workload} pulls an image from a bare IP address", f"Container {name} of {where} uses {image}: images from an IP address instead of a named registry are a common sign of an attacker's workload.", name, image)
    return out


def _rbac_findings() -> tuple[list[dict], bool, str | None]:
    """cluster-admin given to workloads (service accounts outside kube-system) or anything given to anonymous / all users.
    Needs read access to (Cluster)RoleBindings; without it (older install manifest) the check is skipped and the reason reported."""
    now = time.monotonic()
    if now - _rbac_cache["at"] < 300:
        return _rbac_cache["findings"], _rbac_cache["checked"], _rbac_cache["error"]
    found: list[dict] = []
    try:
        bindings = [("ClusterRoleBinding", b) for b in klist("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", cap=5000)[0]]
        bindings += [("RoleBinding", b) for b in klist("/apis/rbac.authorization.k8s.io/v1/rolebindings", cap=20000)[0]]
        checked, error = True, None
    except K8sError as err:
        bindings, checked = [], False
        error = "the agent may not read RBAC bindings: re-apply the install manifest (it now grants read-only access to them)" if err.status in (401, 403) else str(err)[:200]
    for kind, b in bindings:
        name, ns = meta(b).get("name", ""), meta(b).get("namespace", "")
        role = (b.get("roleRef") or {}).get("name", "")
        for subject in b.get("subjects") or []:
            sk, sn, sns = subject.get("kind", ""), subject.get("name", ""), subject.get("namespace", ns)
            label = f"{sk} {sns + '/' if sk == 'ServiceAccount' and sns else ''}{sn}"
            if sn in ("system:anonymous", "system:unauthenticated") or (sn == "system:authenticated" and role == "cluster-admin"):
                found.append({"key": f"rbac_anonymous:{kind}/{ns}/{name}:{sn}", "kind": "k8s_rbac_anonymous", "severity": "critical", "namespace": ns, "object": f"{kind}/{name}",
                              "title": f"{kind} {name} grants {role} to {sn}", "detail": f"{kind} {ns + '/' if ns else ''}{name} gives the role {role} to {sn}: anyone who can reach the API server gets these rights without a valid account.",
                              "created": created(b), "subject": label, "role": role})
            elif kind == "ClusterRoleBinding" and role == "cluster-admin" and sk == "ServiceAccount" and sns not in SYSTEM_NAMESPACES:
                found.append({"key": f"rbac_admin:{name}:{sns}/{sn}", "kind": "k8s_rbac_cluster_admin", "severity": "high", "namespace": sns, "object": f"ClusterRoleBinding/{name}",
                              "title": f"Service account {sns}/{sn} is cluster-admin", "detail": f"ClusterRoleBinding {name} makes service account {sns}/{sn} cluster-admin: any pod running as it (or anyone who steals its token) controls the whole cluster.",
                              "created": created(b), "subject": label, "role": role})
    _rbac_cache.update(at=now, findings=found[:100], checked=checked, error=error)
    return found[:100], checked, error


def security_scan(pods: list[dict]) -> dict:
    findings: dict[str, dict] = {}
    for pod in pods:
        phase = (pod.get("status") or {}).get("phase", "")
        if phase in ("Succeeded", "Failed"):
            continue
        ns = meta(pod).get("namespace", "")
        kind, name = workload_of(pod)
        workload = f"{kind}/{name}"
        system = ns in SYSTEM_NAMESPACES
        for f in _container_findings(ns, workload, pod.get("spec") or {}, created(pod), system):
            findings.setdefault(f["key"], {**f, "pods": 0})["pods"] += 1        # one finding per workload, not per replica
        if kind == "Pod" and ns == "kube-system" and not (meta(pod).get("annotations") or {}).get("kubernetes.io/config.mirror"):
            key = f"bare_pod:{ns}/{name}"
            findings.setdefault(key, {"key": key, "kind": "k8s_bare_pod_system", "severity": "high", "namespace": ns, "object": workload, "container": "", "pods": 1, "created": created(pod),
                                      "title": f"Unmanaged pod {name} in kube-system", "image": ", ".join(c.get("image", "") for c in (pod.get("spec") or {}).get("containers") or [])[:300],
                                      "detail": f"Pod {name} in kube-system has no controller (not part of a Deployment, DaemonSet or static pod). Attackers drop pods there to hide among system components."})
    rbac, rbac_checked, rbac_error = _rbac_findings()
    for f in rbac:
        findings.setdefault(f["key"], f)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    items = sorted(findings.values(), key=lambda f: (order.get(f["severity"], 9), f["key"]))[:300]
    return {"checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "findings": items, "rbac_checked": rbac_checked, "rbac_error": rbac_error}


def summary() -> dict:
    version = kapi("/version").get("gitVersion", "")
    nodes, _ = klist("/api/v1/nodes", cap=1000)
    not_ready = [meta(n)["name"] for n in nodes if not any(c.get("type") == "Ready" and c.get("status") == "True" for c in (n.get("status") or {}).get("conditions") or [])]
    namespaces, _ = klist("/api/v1/namespaces", cap=5000)
    pods, pods_truncated = klist("/api/v1/pods")
    phases = {"Running": 0, "Pending": 0, "Failed": 0, "Succeeded": 0}
    crash, restarts, problems = 0, 0, []
    for pod in pods:
        phase = (pod.get("status") or {}).get("phase", "")
        phases[phase] = phases.get(phase, 0) + 1
        row_status = pod_status(pod)
        pod_restarts = sum(c.get("restartCount", 0) for c in (pod.get("status") or {}).get("containerStatuses") or [])
        restarts += pod_restarts
        if row_status in ("CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull", "CreateContainerConfigError", "OOMKilled", "Error", "RunContainerError") or row_status.startswith("Init:Err") or row_status.startswith("Init:CrashLoop"):
            crash += 1
            if len(problems) < 25:
                problems.append(f"pod {meta(pod).get('namespace')}/{meta(pod).get('name')}: {row_status}" + (f" ({pod_restarts} restarts)" if pod_restarts else ""))
    workloads = {}
    for key, path, ok in (("deployments", "/apis/apps/v1/deployments", lambda i: (i.get("status") or {}).get("availableReplicas", 0) >= (i.get("spec") or {}).get("replicas", 1)),
                          ("statefulsets", "/apis/apps/v1/statefulsets", lambda i: (i.get("status") or {}).get("readyReplicas", 0) >= (i.get("spec") or {}).get("replicas", 1)),
                          ("daemonsets", "/apis/apps/v1/daemonsets", lambda i: (i.get("status") or {}).get("numberReady", 0) >= (i.get("status") or {}).get("desiredNumberScheduled", 0))):
        items, _ = klist(path, cap=5000)
        bad = [i for i in items if not ok(i)]
        workloads[key] = (len(items), len(bad))
        for i in bad[:5]:
            if len(problems) < 25:
                problems.append(f"{key[:-1]} {meta(i).get('namespace')}/{meta(i).get('name')}: not fully available")
    hpas, _ = klist("/apis/autoscaling/v2/horizontalpodautoscalers", cap=5000)
    for name in not_ready:
        problems.insert(0, f"node {name}: NotReady")
    return {
        "agent_version": AGENT_VERSION, "k8s_version": version, "nodes_total": len(nodes), "nodes_ready": len(nodes) - len(not_ready), "not_ready_nodes": not_ready[:20],
        "namespaces": len(namespaces), "pods_total": len(pods), "pods_running": phases.get("Running", 0), "pods_pending": phases.get("Pending", 0),
        "pods_failed": phases.get("Failed", 0), "pods_succeeded": phases.get("Succeeded", 0), "pods_crashloop": crash, "restarts": restarts, "pods_truncated": pods_truncated,
        "deployments_total": workloads["deployments"][0], "deployments_unavailable": workloads["deployments"][1],
        "statefulsets_total": workloads["statefulsets"][0], "statefulsets_unavailable": workloads["statefulsets"][1],
        "daemonsets_total": workloads["daemonsets"][0], "daemonsets_unavailable": workloads["daemonsets"][1], "hpa_total": len(hpas),
        "problems": [p[:200] for p in problems[:30]], **usage_totals(nodes), "security": security_scan(pods),
    }


# ----------------------------------------------------------------------------------------------- talking to the control plane
def _is_internal_host(host: str) -> bool:
    host = host.strip("[]").lower()
    networks = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10")]
    try:
        address = ipaddress.ip_address(host)
        return any(address in n for n in networks if n.version == address.version)
    except ValueError:
        return "." not in host or host.endswith((".local", ".lan", ".internal", ".home.arpa", ".localdomain", ".svc", ".cluster.local"))


def insecure_url_problem() -> str | None:
    parsed = urllib.parse.urlsplit(SMWATCH_URL)
    if parsed.scheme == "https" or AGENT_ALLOW_INSECURE:
        return None
    if parsed.scheme == "http" and parsed.hostname and _is_internal_host(parsed.hostname):
        return None
    return f"{SMWATCH_URL} is not HTTPS and is not a private address: credentials would cross the network unencrypted. Use an https:// address (or set AGENT_ALLOW_INSECURE=1)."


def _control(method: str, path: str, payload: dict | None = None, timeout: float = 20) -> dict:
    request = urllib.request.Request(f"{SMWATCH_URL}{path}", data=json.dumps(payload).encode() if payload is not None else None, method=method,
                                     headers={"Content-Type": "application/json", "Authorization": f"Bearer {_TOKEN}", "User-Agent": f"sm-watch-k8s-agent/{AGENT_VERSION}"})
    with _control_opener.open(request, timeout=timeout) as response:
        return json.loads(response.read().decode() or "{}")


def persist_token(new_token: str) -> None:
    """After a rotation, store the new token in our own Secret (the only write this agent is allowed) so a restart keeps it."""
    try:
        namespace = _read(NAMESPACE_FILE)
        kapi(f"/api/v1/namespaces/{urllib.parse.quote(namespace)}/secrets/{urllib.parse.quote(SECRET_NAME)}", method="PATCH",
             body=json.dumps({"stringData": {"token": new_token}}).encode(), content_type="application/strategic-merge-patch+json")
        log.info("rotated token saved to Secret %s/%s", namespace, SECRET_NAME)
    except Exception as error:
        log.error("could not save the rotated token to its Secret (%s); it applies until the pod restarts", error)


def run_task(task: dict) -> None:
    try:
        output, truncated = run_query(task)
        result = {"ok": True, "output": output, "truncated": truncated}
    except (K8sError, ValueError) as error:
        result = {"ok": False, "error": str(error)[:1500]}
    except Exception as error:
        result = {"ok": False, "error": f"{type(error).__name__}: {error}"[:1500]}
    try:
        _control("POST", f"/api/k8s-agent/tasks/{int(task['id'])}/result", result)
    except Exception as error:
        log.debug("could not deliver result: %s", error)


def task_loop() -> None:
    pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="k8s")
    failures = 0
    while True:
        started = time.monotonic()
        try:
            tasks = _control("GET", "/api/k8s-agent/tasks?wait=20", timeout=35).get("tasks", [])
            failures = 0
            for task in tasks:
                pool.submit(run_task, task)
            if not tasks and time.monotonic() - started < 2:
                time.sleep(3)
        except Exception as error:
            failures += 1
            log.debug("task poll failed: %s", error)
            time.sleep(min(15, 2 * failures))


def report_once() -> int:
    global _TOKEN
    try:
        body = summary()
    except Exception as error:   # e.g. RBAC missing: tell the control plane instead of going silent
        body = {"agent_version": AGENT_VERSION, "error": f"{type(error).__name__}: {error}"[:300]}
        log.error("could not read the cluster: %s", error)
    reply = _control("POST", "/api/k8s-agent/report", body, timeout=20)
    if reply.get("rotate_token") and len(str(reply["rotate_token"])) >= 32 and reply["rotate_token"] != _TOKEN:
        _TOKEN = str(reply["rotate_token"])
        persist_token(_TOKEN)
    if "log_policy" in reply:
        apply_policy(reply["log_policy"])
    return max(10, int(reply.get("interval_seconds", REPORT_INTERVAL)))


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if "--version" in sys.argv:
        print(AGENT_VERSION)
        return
    if "--summary" in sys.argv:   # debugging: print what would be reported
        print(json.dumps(summary(), indent=2))
        return
    if not SMWATCH_URL or len(_TOKEN) < 32:
        sys.exit("SMWATCH_URL and SMWATCH_TOKEN are required (they come from the Secret created by the install manifest)")
    problem = insecure_url_problem()
    if problem:
        sys.exit(problem)
    log.info("SM-Watch Kubernetes agent %s reporting to %s", AGENT_VERSION, SMWATCH_URL)
    interval, started_tasks, failures = REPORT_INTERVAL, False, 0
    while True:
        began = time.monotonic()
        try:
            interval = report_once()
            if failures:
                log.info("connection to the control plane restored")
            failures = 0
            if not started_tasks:   # only after the first accepted report, so the log policy is known before any log request is served
                threading.Thread(target=task_loop, daemon=True, name="tasks").start()
                started_tasks = True
        except urllib.error.HTTPError as error:
            failures += 1
            log.error("control plane rejected the report: HTTP %s%s", error.code, " (token invalid: re-apply the install manifest to get a new one)" if error.code in (401, 403) else "")
        except Exception as error:
            failures += 1
            log.warning("report failed (%s); retrying", error)
        time.sleep(max(1.0, (interval if not failures else min(interval, 5 * 2 ** min(failures - 1, 4))) - (time.monotonic() - began)))


if __name__ == "__main__":
    main()
