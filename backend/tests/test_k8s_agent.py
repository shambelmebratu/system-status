"""The Kubernetes agent's pure logic: parsing, redaction, input validation and the namespace log policy (no cluster needed)."""
import importlib
import os
import sys

os.environ.setdefault("ENVIRONMENT", "test"); os.environ.setdefault("JWT_SECRET", "x" * 40); os.environ.setdefault("ADMIN_PASSWORD", "correct-horse-battery"); os.environ.setdefault("DATABASE_URL", "sqlite://")

import pytest

ROOT = os.path.dirname(os.path.dirname(__file__))


@pytest.fixture()
def k8s(monkeypatch):
    sys.path.insert(0, ROOT)
    sys.modules.pop("k8s_agent", None)
    module = importlib.import_module("k8s_agent")
    module._policy = None
    yield module
    sys.modules.pop("k8s_agent", None)


def test_quantities(k8s):
    assert k8s.cpu_m("250m") == 250 and k8s.cpu_m("2") == 2000 and k8s.cpu_m(None) == 0
    assert k8s.mem_mib("128Mi") == 128 and k8s.mem_mib("1Gi") == 1024 and k8s.mem_mib("1048576Ki") == 1024
    assert k8s.cpu_m("not-a-number") == 0 and k8s.mem_mib("12Zz") == 0       # garbage never raises


def test_describe_output_never_carries_secrets(k8s):
    pod = {"metadata": {"name": "p", "managedFields": [{"x": 1}], "annotations": {"kubectl.kubernetes.io/last-applied-configuration": "{\"password\":\"s3cret\"}", "keep": "me"}},
           "spec": {"containers": [{"name": "c", "env": [{"name": "DB_PASSWORD", "value": "hunter2"}, {"name": "FROM_SECRET", "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}}}]}]}}
    out = k8s.redact(pod)
    text = str(out)
    assert "hunter2" not in text and "s3cret" not in text and "managedFields" not in text
    assert out["metadata"]["annotations"] == {"keep": "me"}
    env = out["spec"]["containers"][0]["env"]
    assert env[0]["value"] == "<redacted>" and env[1]["valueFrom"]["secretKeyRef"]["name"] == "s"   # references stay, values go


@pytest.mark.parametrize("field,value", [("namespace", "../kube-system"), ("namespace", "A_B"), ("namespace", "a b"), ("name", "x/../../secrets"), ("name", "a;b"), ("name", "$(id)"), ("container", "-x y"), ("container", "a/b")])
def test_task_fields_are_validated(k8s, field, value):
    with pytest.raises(ValueError):
        k8s.check({"kind": "pods", field: value})


def test_valid_fields_pass(k8s):
    k8s.check({"kind": "logs", "namespace": "kube-system", "name": "coredns-5d78c9869d-abcde", "container": "coredns"})
    k8s.check({"kind": "pods"})


def test_namespace_log_policy(k8s):
    assert k8s.logs_allowed("anything")                                            # no policy received yet: control plane decides
    k8s.apply_policy({"enabled": True, "include": ["*"], "exclude": ["kube-*", "smwatch"]})
    assert k8s.logs_allowed("demo") and not k8s.logs_allowed("kube-system") and not k8s.logs_allowed("smwatch")
    k8s.apply_policy({"enabled": False, "include": ["*"], "exclude": []})
    assert not k8s.logs_allowed("demo")
    k8s.apply_policy({"enabled": "yes", "include": "*"})                            # malformed: ignored, previous policy stays
    k8s.apply_policy(None); k8s.apply_policy({"include": []})
    assert not k8s.logs_allowed("demo")


def test_agent_and_control_plane_agree_on_namespaces(k8s):
    from app.routes_k8s import namespace_allowed
    policy = {"enabled": True, "include": ["prod-*", "demo"], "exclude": ["prod-secret*"]}
    k8s.apply_policy(policy)
    for ns in ["demo", "prod-web", "prod-secrets", "kube-system", "other", ""]:
        assert k8s.logs_allowed(ns) == namespace_allowed(policy, ns), ns


def test_plain_http_to_the_internet_is_refused(k8s, monkeypatch):
    monkeypatch.setattr(k8s, "SMWATCH_URL", "http://203.0.113.5:8000")
    monkeypatch.setattr(k8s, "AGENT_ALLOW_INSECURE", False)
    assert k8s.insecure_url_problem()
    monkeypatch.setattr(k8s, "SMWATCH_URL", "https://monitor.example.com")
    assert not k8s.insecure_url_problem()


def _fake_cluster(k8s, monkeypatch):
    pod = lambda name, labels, owner=None, claim=None: {"metadata": {"name": name, "namespace": "erp", "labels": labels, "ownerReferences": [owner] if owner else []},
                                                         "spec": {"nodeName": "node-1", "containers": [{"name": "app", "image": "erp:1"}], "volumes": [{"name": "d", "persistentVolumeClaim": {"claimName": claim}}] if claim else []},
                                                         "status": {"phase": "Running", "containerStatuses": [{"name": "app", "ready": True, "restartCount": 0, "state": {"running": {}}}]}}
    objects = {
        "/apis/apps/v1/namespaces/erp/deployments/api": {"metadata": {"name": "api", "namespace": "erp"}, "spec": {"selector": {"matchLabels": {"app": "api"}, "matchExpressions": [{"key": "tier", "operator": "In", "values": ["web", "edge"]}]}}},
        "/apis/apps/v1/namespaces/erp/replicasets/api-7d9f": {"metadata": {"name": "api-7d9f", "ownerReferences": [{"kind": "Deployment", "name": "api"}]}},
        "/api/v1/namespaces/erp/services/api": {"metadata": {"name": "api", "namespace": "erp"}, "spec": {"selector": {"app": "api"}, "ports": [{"port": 80, "targetPort": 8000}]}},
    }
    pods = [pod("api-7d9f-a", {"app": "api", "tier": "web"}, {"kind": "ReplicaSet", "name": "api-7d9f"}, claim="data"), pod("api-7d9f-b", {"app": "api", "tier": "web"}, {"kind": "ReplicaSet", "name": "api-7d9f"}), pod("worker-1", {"app": "worker"})]
    objects["/api/v1/namespaces/erp/pods/api-7d9f-a"] = pods[0]
    services = [objects["/api/v1/namespaces/erp/services/api"], {"metadata": {"name": "other", "namespace": "erp"}, "spec": {"selector": {"app": "nope"}}}]
    events = [{"involvedObject": {"name": n}, "type": t, "reason": r, "message": m, "lastTimestamp": ts, "count": 1, "metadata": {"namespace": "erp"}}
              for n, t, r, m, ts in (("api", "Normal", "ScalingReplicaSet", "Scaled up", "2026-11-16T10:00:00Z"), ("api-7d9f-b", "Warning", "BackOff", "Back-off restarting", "2026-11-16T11:00:00Z"), ("worker-1", "Warning", "OOMKilled", "x", "2026-11-16T12:00:00Z"))]
    seen = []

    def klist(path, params=None, cap=0):
        seen.append((path, dict(params or {})))
        if path.endswith("/pods"):
            sel = (params or {}).get("labelSelector")
            if sel:
                assert sel in ("app=api,tier in (web,edge)", "app=api"), sel
                return [p for p in pods if p["metadata"]["labels"].get("app") == "api"], False
            return pods, False
        if path.endswith("/services"):
            return services, False
        if path.endswith("/events"):
            return events, False
        return [], False

    def kapi(path, *a, **kw):
        return objects[path]

    monkeypatch.setattr(k8s, "klist", klist); monkeypatch.setattr(k8s, "kapi", kapi)
    return seen


def test_related_for_a_workload_pod_and_service(k8s, monkeypatch):
    _fake_cluster(k8s, monkeypatch)
    out = k8s.related("deployment", "erp", "api")
    assert [p["name"] for p in out["pods"]] == ["api-7d9f-a", "api-7d9f-b"] and out["selector"] == "app=api,tier in (web,edge)"
    assert [s["name"] for s in out["services"]] == ["api"]
    assert [e["reason"] for e in out["events"]] == ["BackOff", "ScalingReplicaSet"]          # the workload's and its pods' events, newest first; not worker-1's
    pod = k8s.related("pod", "erp", "api-7d9f-a")
    assert {(l["kind"], l["name"]) for l in pod["links"]} == {("ReplicaSet", "api-7d9f"), ("Deployment", "api"), ("PersistentVolumeClaim", "data"), ("Node", "node-1")}
    assert [s["name"] for s in pod["services"]] == ["api"] and len(pod["pods"]) == 1
    svc = k8s.related("service", "erp", "api")
    assert [p["name"] for p in svc["pods"]] == ["api-7d9f-a", "api-7d9f-b"] and svc["selector"] == "app=api"
    text, _ = k8s.run_query({"kind": "related", "resource": "deployment", "namespace": "erp", "name": "api"})
    assert '"pods"' in text
    with pytest.raises(ValueError):
        k8s.run_query({"kind": "related", "resource": "deployment", "name": "api"})          # namespace required
