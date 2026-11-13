"""Kubernetes cluster monitoring (read-only).

An in-cluster agent with a read-only ServiceAccount makes OUTBOUND connections only: it reports a small summary every 30 s and
answers on-demand questions the dashboard queues (list pods, read logs, ...), exactly like the server agents. Nothing about the
cluster's objects or logs is stored beyond a short time-series of counts and usage totals."""
import asyncio
import fnmatch
import json
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session

from .agent_versions import is_outdated, latest_k8s_agent
from .audit import audit
from .config import get_settings, resolved_k8s_agent_image
from .database import SessionLocal, get_db
from .models import CheckResult, Cluster, ClusterSample, Incident, K8sRequest
from .monitoring import format_alert, outage_seconds, queue_event, record_result, should_notify_again, sync_incident
from .routes_agent import hash_token
from .routes_enroll import control_plane_url, find_enrollment
from .routes_logs import _Waiter, _wake, pickup_timeout, request_ttl
from .security import RANK, agent_gate, client_ip, login_limiter, require_admin, require_operator, require_user
from .stats import aware, bucketize

router = APIRouter(tags=["kubernetes"])

NAME_PATTERN = r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,58}[A-Za-z0-9])?$"
NS = r"^([a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)?$"
KINDS = "namespaces|nodes|pods|deployments|statefulsets|daemonsets|jobs|cronjobs|services|ingresses|hpa|events|pvcs|quotas|pod_metrics|node_metrics|describe|logs"
# Limits come from .env (K8S_* settings), see config.py.


# ---------------------------------------------------------------------------------------------------------------- schemas
class K8sQuery(BaseModel):
    kind: str = Field(pattern=f"^({KINDS})$")
    resource: str = Field(default="", pattern="^(|pod|deployment|statefulset|daemonset|job|cronjob|service|ingress|hpa|pvc|node|namespace)$")
    namespace: str = Field(default="", pattern=NS)
    name: str = Field(default="", pattern=r"^([a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?)?$")
    container: str = Field(default="", pattern=r"^([A-Za-z0-9]([-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?)?$")
    limit: int = Field(default=200, ge=1, le=500)
    lines: int = Field(default=200, ge=1, le=2000)
    since_minutes: int = Field(default=0, ge=0, le=10080)
    previous: bool = False
    grep: str = Field(default="", max_length=200)
    warnings_only: bool = False


class K8sResult(BaseModel):
    ok: bool
    output: str = Field(default="", max_length=900_000)
    error: str = Field(default="", max_length=2000)
    truncated: bool = False


class K8sReport(BaseModel):
    agent_version: str = Field(default="", max_length=32)
    k8s_version: str = Field(default="", max_length=40)
    error: str = Field(default="", max_length=400)
    nodes_total: int = Field(default=0, ge=0, le=100000)
    nodes_ready: int = Field(default=0, ge=0, le=100000)
    not_ready_nodes: list[str] = Field(default_factory=list, max_length=20)
    namespaces: int = Field(default=0, ge=0, le=1000000)
    pods_total: int = Field(default=0, ge=0, le=10000000)
    pods_running: int = Field(default=0, ge=0, le=10000000)
    pods_pending: int = Field(default=0, ge=0, le=10000000)
    pods_failed: int = Field(default=0, ge=0, le=10000000)
    pods_succeeded: int = Field(default=0, ge=0, le=10000000)
    pods_crashloop: int = Field(default=0, ge=0, le=10000000)
    restarts: int = Field(default=0, ge=0, le=100000000)
    pods_truncated: bool = False
    deployments_total: int = Field(default=0, ge=0, le=1000000)
    deployments_unavailable: int = Field(default=0, ge=0, le=1000000)
    statefulsets_total: int = Field(default=0, ge=0, le=1000000)
    statefulsets_unavailable: int = Field(default=0, ge=0, le=1000000)
    daemonsets_total: int = Field(default=0, ge=0, le=1000000)
    daemonsets_unavailable: int = Field(default=0, ge=0, le=1000000)
    hpa_total: int = Field(default=0, ge=0, le=1000000)
    usage_available: bool = False
    cpu_m: float | None = Field(default=None, ge=0)
    cpu_alloc_m: float | None = Field(default=None, ge=0)
    mem_mib: float | None = Field(default=None, ge=0)
    mem_alloc_mib: float | None = Field(default=None, ge=0)
    problems: list[str] = Field(default_factory=list, max_length=30)

    @field_validator("problems", "not_ready_nodes")
    @classmethod
    def short_printable_items(cls, v: list[str]) -> list[str]:   # text from the cluster ends up in alerts: bounded and without control characters
        return [" ".join("".join(ch if ch.isprintable() else " " for ch in item).split())[:300] for item in v]

    @field_validator("error", "agent_version", "k8s_version")
    @classmethod
    def printable_only(cls, v: str) -> str:
        return " ".join("".join(ch if ch.isprintable() else " " for ch in v).split())


class ClusterUpdate(BaseModel):
    name: str | None = Field(default=None, pattern=NAME_PATTERN)
    enabled: bool | None = None


class K8sLogPolicy(BaseModel):
    """Which namespaces' pod logs the dashboard may read from this cluster."""
    enabled: bool = True
    include: list[str] = Field(default_factory=lambda: ["*"], max_length=50)
    exclude: list[str] = Field(default_factory=list, max_length=50)

    def clean(self) -> "K8sLogPolicy":
        import re
        for values in (self.include, self.exclude):
            for v in values:
                if not re.match(r"^[a-z0-9*?\[\]-]{1,63}$", v):
                    raise HTTPException(422, f"Invalid namespace pattern '{v}' (lowercase letters, digits, - * ? [ ] only)")
        return self


def parse_policy(raw: str | None) -> dict:
    try:
        value = json.loads(raw) if raw else None
        return K8sLogPolicy.model_validate(value).model_dump() if value else K8sLogPolicy().model_dump()
    except (ValueError, TypeError):
        return K8sLogPolicy().model_dump()


def namespace_allowed(policy: dict, namespace: str) -> bool:
    return bool(policy["enabled"]) and any(fnmatch.fnmatchcase(namespace, p) for p in policy["include"]) and not any(fnmatch.fnmatchcase(namespace, p) for p in policy["exclude"])


# ---------------------------------------------------------------------------------------------------------------- helpers
def serialize_cluster(c: Cluster) -> dict:
    iso = lambda v: aware(v).isoformat() if v else None  # noqa: E731
    try:
        summary = json.loads(c.summary) if c.summary else None
    except ValueError:
        summary = None
    return {
        "id": c.id, "name": c.name, "enabled": c.enabled, "status": c.last_status, "last_error": c.last_error, "last_seen_at": iso(c.last_seen_at),
        "k8s_version": c.k8s_version, "agent_version": c.agent_version, "agent_outdated": is_outdated(c.agent_version, latest_k8s_agent()), "latest_agent_version": latest_k8s_agent(), "summary": summary, "token_issued_at": iso(c.token_issued_at),
        "token_rotation_pending": bool(c.pending_token_hash), "last_agent_ip": c.last_agent_ip, "created_by": c.created_by, "created_at": iso(c.created_at),
        "log_policy": parse_policy(c.log_policy), "restricted": parse_policy(c.log_policy) != K8sLogPolicy().model_dump(),
    }


def get_cluster(db: Session, cluster_id: int) -> Cluster:
    cluster = db.get(Cluster, cluster_id)
    if not cluster:
        raise HTTPException(404, "Cluster not found")
    return cluster


def evaluate(report: K8sReport) -> tuple[str, str | None]:
    """up / alert from a report. (The worker marks a silent cluster 'down'.)"""
    if report.error:
        return "alert", f"The agent cannot read the cluster: {report.error}"
    unavailable = report.deployments_unavailable + report.statefulsets_unavailable + report.daemonsets_unavailable
    if report.nodes_ready < report.nodes_total or report.pods_crashloop > 0 or unavailable > 0:
        head = report.problems[:4]
        return "alert", "; ".join(head) if head else f"{report.nodes_total - report.nodes_ready} node(s) not ready, {report.pods_crashloop} pod(s) failing, {unavailable} workload(s) unavailable"
    return "up", None


def cluster_where(cluster: Cluster) -> str | None:
    bits = [f"Kubernetes {cluster.k8s_version}" if cluster.k8s_version else "", cluster.last_agent_ip or ""]
    return " · ".join(b for b in bits if b) or None


def apply_cluster_status(db: Session, cluster: Cluster, status: str, detail: str | None, deliver: bool = False) -> None:
    previous = cluster.last_status
    now = datetime.now(timezone.utc)
    if cluster.last_checked_at is None or (now - aware(cluster.last_checked_at)).total_seconds() >= 55 or previous != status:
        record_result(db, "cluster", cluster.id, status, None, None, detail)   # uptime history, at most about once a minute
    cluster.last_status, cluster.last_error, cluster.last_checked_at = status, detail if status != "up" else None, now
    resolved = sync_incident(db, "cluster", cluster, status, detail, alert_title=f"{cluster.name} has problems")
    if status in ("down", "alert"):
        if previous != status or should_notify_again(db, "cluster", cluster.id):
            problems = (json.loads(cluster.summary).get("problems") if cluster.summary else None) if status == "alert" else None
            state = status if previous != status else f"still_{status}"
            queue_event(db, "cluster", cluster, "critical", format_alert("Cluster", state, cluster.name, problems or detail, at=now, where=cluster_where(cluster)), deliver)
    elif previous in ("down", "alert"):
        queue_event(db, "cluster", cluster, "info", format_alert("Cluster", "recovered", cluster.name, "All nodes are ready and workloads are healthy.", at=now, duration=outage_seconds(resolved), where=cluster_where(cluster)), deliver)


def check_cluster_heartbeats(session: Session) -> None:
    """Called by the worker every second: a cluster whose agent has gone silent is marked down (and alerts)."""
    now = datetime.now(timezone.utc)
    cfg = get_settings()
    for cluster in session.scalars(select(Cluster).where(Cluster.enabled.is_(True), Cluster.last_seen_at.is_not(None))).all():
        silent = (now - aware(cluster.last_seen_at)).total_seconds()
        if silent > cfg.k8s_heartbeat_grace_seconds and (cluster.last_checked_at is None or (now - aware(cluster.last_checked_at)).total_seconds() >= cfg.k8s_report_interval_seconds or cluster.last_status != "down"):
            apply_cluster_status(session, cluster, "down", f"No agent heartbeat for {int(silent)}s", deliver=True)


def set_token(cluster: Cluster, token: str) -> None:
    cluster.agent_token, cluster.token_hash, cluster.token_issued_at = token, hash_token(token), datetime.now(timezone.utc)
    cluster.pending_token = cluster.pending_token_hash = cluster.pending_token_at = None


# ---------------------------------------------------------------------------------------------------------------- manifest
def build_manifest(name: str, token: str, url: str, image: str) -> str:
    q = json.dumps  # JSON strings are valid YAML scalars: quoting for free
    pull = "Always" if image.endswith(":latest") else "IfNotPresent"
    return f"""# SM-Watch Kubernetes agent: read-only cluster access, outbound connections only.
# Cluster: {name}. Registered with the control plane at {url}.
apiVersion: v1
kind: Namespace
metadata:
  name: smwatch
  labels:
    app.kubernetes.io/name: sm-watch-agent
    pod-security.kubernetes.io/enforce: restricted
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: smwatch-agent
  namespace: smwatch
---
# Cluster-wide READ-ONLY. Deliberately absent: secrets, configmaps, pods/exec, pods/attach, and every write verb.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: smwatch-agent-read
rules:
  - apiGroups: [""]
    resources: [namespaces, nodes, pods, pods/log, services, endpoints, events, persistentvolumeclaims, resourcequotas]
    verbs: [get, list, watch]
  - apiGroups: [apps]
    resources: [deployments, statefulsets, daemonsets, replicasets]
    verbs: [get, list, watch]
  - apiGroups: [batch]
    resources: [jobs, cronjobs]
    verbs: [get, list, watch]
  - apiGroups: [autoscaling]
    resources: [horizontalpodautoscalers]
    verbs: [get, list, watch]
  - apiGroups: [networking.k8s.io]
    resources: [ingresses]
    verbs: [get, list, watch]
  - apiGroups: [metrics.k8s.io]
    resources: [pods, nodes]
    verbs: [get, list]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: smwatch-agent-read
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: smwatch-agent-read
subjects:
  - kind: ServiceAccount
    name: smwatch-agent
    namespace: smwatch
---
# The ONLY write permission: the agent may update its own token Secret (so a rotated token survives a restart). Nothing else.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: smwatch-agent-token
  namespace: smwatch
rules:
  - apiGroups: [""]
    resources: [secrets]
    resourceNames: [smwatch-agent]
    verbs: [get, patch]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: smwatch-agent-token
  namespace: smwatch
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: smwatch-agent-token
subjects:
  - kind: ServiceAccount
    name: smwatch-agent
    namespace: smwatch
---
apiVersion: v1
kind: Secret
metadata:
  name: smwatch-agent
  namespace: smwatch
type: Opaque
stringData:
  url: {q(url)}
  token: {q(token)}
  cluster: {q(name)}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: smwatch-agent
  namespace: smwatch
  labels:
    app.kubernetes.io/name: sm-watch-agent
spec:
  replicas: 1
  strategy:
    type: Recreate
  selector:
    matchLabels:
      app.kubernetes.io/name: sm-watch-agent
  template:
    metadata:
      labels:
        app.kubernetes.io/name: sm-watch-agent
    spec:
      serviceAccountName: smwatch-agent
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: agent
          image: {q(image)}
          imagePullPolicy: {pull}
          env:
            - name: SMWATCH_URL
              valueFrom:
                secretKeyRef: {{name: smwatch-agent, key: url}}
            - name: SMWATCH_TOKEN
              valueFrom:
                secretKeyRef: {{name: smwatch-agent, key: token}}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: [ALL]
          resources:
            requests: {{cpu: 20m, memory: 48Mi}}
            limits: {{cpu: 250m, memory: 192Mi}}
"""


@router.post("/api/agent/k8s/{token}", response_class=PlainTextResponse)
def register_cluster(token: str, request: Request, name: str = Query(pattern=NAME_PATTERN), db: Session = Depends(get_db)) -> str:
    """`curl -X POST .../api/agent/k8s/<join-link>?name=prod | kubectl apply -f -`: registers the cluster and returns its install manifest."""
    gate = agent_gate(request, "join")
    enrollment = find_enrollment(db, token)
    if enrollment is None:
        if login_limiter.fail_unique(gate, token):
            audit(db, request, "k8s.register", actor=f"agent:{name}", success=False, detail="invalid, expired or revoked install link", commit=True)
        raise HTTPException(401, "This install link is invalid, expired or revoked. Create a new one in the dashboard.")
    cluster = db.scalar(select(Cluster).where(Cluster.name == name))
    now = datetime.now(timezone.utc)
    if cluster is None:
        if enrollment.max_uses is not None and enrollment.uses >= enrollment.max_uses:
            raise HTTPException(403, "This install link has reached its maximum number of uses.")
        cluster = Cluster(name=name, created_by=enrollment.created_by)
        db.add(cluster)
        enrollment.uses += 1
    elif cluster.last_seen_at is not None and (now - aware(cluster.last_seen_at)).total_seconds() < 600:
        # Re-issuing a token would cut off the running agent: a link must not be able to take over a live cluster by name.
        if login_limiter.first_time(f"k8s-taken:{client_ip(request)}:{name}"):
            audit(db, request, "k8s.register", actor=f"agent:{name}", success=False, detail="a cluster with that name is connected", commit=True)
        raise HTTPException(409, f"A cluster named '{name}' is already connected. Choose another name, or rotate its token in the dashboard.")
    new_token = secrets.token_urlsafe(32)
    set_token(cluster, new_token)
    enrollment.last_used_at = now
    db.flush()
    audit(db, request, "k8s.register", actor=f"agent:{name}", target=f"cluster:{cluster.id}", detail=f"registered via link {enrollment.id} ({enrollment.label or 'unnamed'})")
    db.commit()
    return build_manifest(name, new_token, control_plane_url(request), resolved_k8s_agent_image(get_settings()))


# ---------------------------------------------------------------------------------------------------------------- agent side
def _cluster_by_token(db: Session, authorization: str | None) -> tuple[Cluster | None, str | None]:
    token = authorization[7:] if authorization and authorization.startswith("Bearer ") else ""
    digest = hash_token(token) if token else None
    cluster = db.scalar(select(Cluster).where(or_(Cluster.token_hash == digest, Cluster.pending_token_hash == digest))) if digest else None
    return cluster, digest


@router.post("/api/k8s-agent/report")
def agent_report(payload: K8sReport, request: Request, authorization: str | None = Header(default=None), db: Session = Depends(get_db)) -> dict:
    gate = agent_gate(request, "k8s")
    cluster, digest = _cluster_by_token(db, authorization)
    if cluster is None:
        if login_limiter.fail_unique(gate, digest or ""):
            audit(db, request, "agent.auth_failed", actor="agent:k8s", detail="cluster report with an unknown token", success=False, commit=True)
        raise HTTPException(401, "Invalid agent token")
    if not cluster.enabled:
        raise HTTPException(403, "This cluster is disabled")
    now = datetime.now(timezone.utc)
    if cluster.last_seen_at and (now - aware(cluster.last_seen_at)).total_seconds() < get_settings().agent_min_report_seconds:
        raise HTTPException(429, "Reporting too frequently", headers={"Retry-After": "2"})
    reply: dict = {"ok": True}
    if cluster.pending_token_hash and digest == cluster.pending_token_hash:
        set_token(cluster, cluster.pending_token)
        audit(db, request, "agent.token_rotated", actor=f"agent:{cluster.name}", target=f"cluster:{cluster.id}", detail="agent switched to the new token; the old one is now invalid")
    elif cluster.pending_token_hash:
        reply["rotate_token"] = cluster.pending_token
    ip = client_ip(request)
    if cluster.last_agent_ip and cluster.last_agent_ip != ip:
        audit(db, request, "agent.ip_changed", actor=f"agent:{cluster.name}", target=f"cluster:{cluster.id}", detail=f"{cluster.last_agent_ip} -> {ip}")
    cluster.last_agent_ip, cluster.last_seen_at = ip, now
    cluster.agent_version, cluster.k8s_version = payload.agent_version or cluster.agent_version, payload.k8s_version or cluster.k8s_version
    cluster.summary = payload.model_dump_json()
    if not payload.error:
        db.add(ClusterSample(cluster_id=cluster.id, ts=now, nodes_ready=payload.nodes_ready, nodes_total=payload.nodes_total, pods_running=payload.pods_running, pods_total=payload.pods_total,
                             pods_failing=payload.pods_crashloop + payload.pods_failed, cpu_m=payload.cpu_m, cpu_alloc_m=payload.cpu_alloc_m, mem_mib=payload.mem_mib, mem_alloc_mib=payload.mem_alloc_mib))
    status, detail = evaluate(payload)
    apply_cluster_status(db, cluster, status, detail, deliver=False)   # alerts are queued; the worker delivers them
    db.commit()
    return {**reply, "interval_seconds": get_settings().k8s_report_interval_seconds, "log_policy": parse_policy(cluster.log_policy)}


def _claim(authorization: str | None) -> tuple[int, list[dict]]:
    with SessionLocal() as db:
        cluster, _ = _cluster_by_token(db, authorization)
        if cluster is None:
            raise HTTPException(401, "Invalid agent token")
        if not cluster.enabled:
            raise HTTPException(403, "This cluster is disabled")
        fresh = datetime.now(timezone.utc) - pickup_timeout()
        items = db.scalars(select(K8sRequest).where(K8sRequest.cluster_id == cluster.id, K8sRequest.status == "pending", K8sRequest.created_at >= fresh).order_by(K8sRequest.id).limit(get_settings().k8s_max_pending_requests)).all()
        tasks = []
        for item in items:
            item.status = "running"
            tasks.append({"id": item.id, **json.loads(item.query)})
        if tasks:
            db.commit()
        return cluster.id, tasks


_task_waiters: dict = {}
_result_waiters: dict = {}


@router.get("/api/k8s-agent/tasks")
async def agent_tasks(request: Request, wait: int = Query(0, ge=0, le=25), authorization: str | None = Header(default=None)) -> dict:
    gate = agent_gate(request, "k8s")
    loop = asyncio.get_running_loop()
    deadline = loop.time() + wait
    try:
        cluster_id, tasks = await run_in_threadpool(_claim, authorization)
    except HTTPException as error:
        if error.status_code == 401:
            login_limiter.fail_unique(gate, authorization or "")
        raise
    if tasks or wait == 0:
        return {"tasks": tasks}
    if len(_task_waiters.get(cluster_id, ())) >= get_settings().agent_max_open_polls:
        raise HTTPException(429, "Too many open task polls for this agent", headers={"Retry-After": "5"})
    with _Waiter(_task_waiters, cluster_id) as event:
        while not tasks and loop.time() < deadline:
            event.clear()
            _, tasks = await run_in_threadpool(_claim, authorization)
            if tasks:
                break
            try:
                await asyncio.wait_for(event.wait(), timeout=min(max(deadline - loop.time(), 0.01), 2.0))
            except asyncio.TimeoutError:
                pass
    return {"tasks": tasks}


@router.post("/api/k8s-agent/tasks/{request_id}/result")
def agent_result(request_id: int, payload: K8sResult, request: Request, authorization: str | None = Header(default=None), db: Session = Depends(get_db)) -> dict:
    gate = agent_gate(request, "k8s")
    cluster, _ = _cluster_by_token(db, authorization)
    if cluster is None:
        login_limiter.fail_unique(gate, authorization or "")
        raise HTTPException(401, "Invalid agent token")
    if not cluster.enabled:
        raise HTTPException(403, "This cluster is disabled")
    item = db.get(K8sRequest, request_id)
    if not item or item.cluster_id != cluster.id or item.status != "running":
        raise HTTPException(404, "Unknown task")
    item.status = "done" if payload.ok else "error"
    item.output, item.error, item.truncated, item.completed_at = payload.output, payload.error or None, payload.truncated, datetime.now(timezone.utc)
    db.commit()
    _wake(_result_waiters, request_id)
    return {"ok": True}


# ---------------------------------------------------------------------------------------------------------------- dashboard side
@router.get("/api/clusters")
def list_clusters(_: dict = Depends(require_user), db: Session = Depends(get_db)) -> list[dict]:
    return [serialize_cluster(c) for c in db.scalars(select(Cluster).order_by(Cluster.name)).all()]


@router.get("/api/clusters/{cluster_id}")
def read_cluster(cluster_id: int, _: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict:
    return serialize_cluster(get_cluster(db, cluster_id))


@router.put("/api/clusters/{cluster_id}")
def update_cluster(cluster_id: int, payload: ClusterUpdate, request: Request, user: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
    cluster = get_cluster(db, cluster_id)
    changes = []
    if payload.name and payload.name != cluster.name:
        if db.scalar(select(Cluster.id).where(Cluster.name == payload.name)) is not None:
            raise HTTPException(409, "A cluster with that name already exists")
        changes.append(f"renamed {cluster.name} -> {payload.name}")
        cluster.name = payload.name
    if payload.enabled is not None and payload.enabled != cluster.enabled:
        cluster.enabled = payload.enabled
        changes.append("enabled" if payload.enabled else "disabled")
    if changes:
        audit(db, request, "k8s.cluster_update", user=user, target=f"cluster:{cluster.id}", detail="; ".join(changes))
    db.commit(); db.refresh(cluster)
    return serialize_cluster(cluster)


@router.delete("/api/clusters/{cluster_id}")
def delete_cluster(cluster_id: int, request: Request, user: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict[str, bool]:
    cluster = db.get(Cluster, cluster_id)
    if cluster:
        audit(db, request, "k8s.cluster_delete", user=user, target=f"cluster:{cluster.id}", detail=cluster.name)
        db.execute(delete(CheckResult).where(CheckResult.target_type == "cluster", CheckResult.target_id == cluster.id))
        db.execute(delete(Incident).where(Incident.target_type == "cluster", Incident.target_id == cluster.id))
        db.execute(delete(ClusterSample).where(ClusterSample.cluster_id == cluster.id))
        db.execute(delete(K8sRequest).where(K8sRequest.cluster_id == cluster.id))
        db.delete(cluster); db.commit()
    return {"deleted": True}


@router.post("/api/clusters/{cluster_id}/rotate-token")
def rotate_cluster_token(cluster_id: int, request: Request, immediate: bool = Query(False), user: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
    """Managed (default): the new token is delivered to the agent over its own connection and saved to its Secret. immediate=true:
    the old token dies now and the new one is returned once (patch the Secret by hand)."""
    cluster = get_cluster(db, cluster_id)
    token = secrets.token_urlsafe(32)
    if cluster.last_seen_at and not immediate:
        cluster.pending_token, cluster.pending_token_hash, cluster.pending_token_at = token, hash_token(token), datetime.now(timezone.utc)
        audit(db, request, "k8s.token_rotate", user=user, target=f"cluster:{cluster.id}", detail=f"{cluster.name}: staged for delivery to the agent")
        db.commit()
        return {"mode": "managed", "detail": "The new token will be delivered to the agent at its next report and saved to its Secret."}
    set_token(cluster, token)
    audit(db, request, "k8s.token_revoke", user=user, target=f"cluster:{cluster.id}", detail=f"{cluster.name}: old token invalidated immediately")
    db.commit()
    return {"mode": "immediate", "install_token": token}


@router.get("/api/clusters/{cluster_id}/log-policy")
def get_policy(cluster_id: int, _: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
    return parse_policy(get_cluster(db, cluster_id).log_policy)


@router.put("/api/clusters/{cluster_id}/log-policy")
def set_policy(cluster_id: int, policy: K8sLogPolicy, request: Request, user: dict = Depends(require_admin), db: Session = Depends(get_db)) -> dict:
    cluster = get_cluster(db, cluster_id)
    policy.clean()
    cluster.log_policy = None if policy.model_dump() == K8sLogPolicy().model_dump() else policy.model_dump_json()
    audit(db, request, "k8s.log_policy", user=user, target=f"cluster:{cluster.id}", detail=f"{cluster.name}: logs {'off' if not policy.enabled else ','.join(policy.include)}" + (f" except {','.join(policy.exclude)}" if policy.exclude else ""))
    db.commit()
    return policy.model_dump()


@router.post("/api/clusters/{cluster_id}/query")
def ask(cluster_id: int, payload: K8sQuery, request: Request, user: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict:
    cluster = get_cluster(db, cluster_id)
    if payload.kind == "logs":
        if RANK.get(user["role"], 0) < RANK["operator"]:
            raise HTTPException(403, f"Your role ({user['role']}) cannot read pod logs. It needs the operator role.")
        if not payload.namespace or not payload.name:
            raise HTTPException(422, "Choose a namespace and a pod")
        if not namespace_allowed(parse_policy(cluster.log_policy), payload.namespace):
            audit(db, request, "k8s.logs.denied", user=user, target=f"cluster:{cluster.id}", success=False, detail=f"{payload.namespace}/{payload.name} blocked by the cluster's log policy", commit=True)
            raise HTTPException(403, f"This cluster's log policy does not allow reading logs in namespace '{payload.namespace}'. An admin can change it in the cluster's settings.")
    if payload.kind == "describe":
        if not payload.resource or not payload.name:
            raise HTTPException(422, "Choose a resource and a name")
        if payload.resource not in ("node", "namespace") and not payload.namespace:
            raise HTTPException(422, "A namespace is required for this resource")
    now = datetime.now(timezone.utc)
    if not cluster.last_seen_at or (now - aware(cluster.last_seen_at)).total_seconds() > get_settings().k8s_offline_seconds:
        raise HTTPException(503, f"The cluster agent is offline (no report in the last {get_settings().k8s_offline_seconds // 60 or 1} min).")
    db.execute(delete(K8sRequest).where(K8sRequest.created_at < now - request_ttl()))
    pending = db.scalar(select(func.count()).select_from(K8sRequest).where(K8sRequest.cluster_id == cluster_id, K8sRequest.status.in_(("pending", "running")), K8sRequest.created_at >= now - pickup_timeout())) or 0
    if pending >= get_settings().k8s_max_pending_requests:
        raise HTTPException(429, "Too many requests are already waiting for this cluster")
    item = K8sRequest(cluster_id=cluster_id, query=payload.model_dump_json())
    db.add(item)
    if payload.kind == "logs":   # logs can contain secrets: record who read which pod's logs (never the content)
        audit(db, request, "k8s.logs.read", user=user, target=f"cluster:{cluster.id}", detail=f"{payload.namespace}/{payload.name}" + (f" container={payload.container}" if payload.container else "") + f" lines={payload.lines}" + (f" filter={payload.grep!r}" if payload.grep else ""))
    db.commit(); db.refresh(item)
    _wake(_task_waiters, cluster_id)
    return {"id": item.id}


def _read(cluster_id: int, request_id: int) -> dict:
    with SessionLocal() as db:
        item = db.get(K8sRequest, request_id)
        if not item or item.cluster_id != cluster_id:
            raise HTTPException(404, "Request not found (results are kept for 15 minutes)")
        status, error = item.status, item.error
        if status in ("pending", "running") and datetime.now(timezone.utc) - aware(item.created_at) > pickup_timeout():
            status, error = "error", "The cluster agent did not answer in time."
        query = json.loads(item.query)
        result = {"id": item.id, "status": status, "error": error, "truncated": item.truncated, "query": query}
        if status == "done":
            if query["kind"] == "logs":
                result["text"] = item.output or ""
            else:
                try:
                    result["data"] = json.loads(item.output or "{}")
                except ValueError:
                    result["status"], result["error"] = "error", "The agent returned an unreadable answer"
        return result


@router.get("/api/clusters/{cluster_id}/query/{request_id}")
async def read_query(cluster_id: int, request_id: int, wait: int = Query(0, ge=0, le=20), _: dict = Depends(require_user)) -> dict:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + wait
    with _Waiter(_result_waiters, request_id) as event:
        while True:
            event.clear()
            result = await run_in_threadpool(_read, cluster_id, request_id)
            remaining = deadline - loop.time()
            if result["status"] in ("done", "error") or remaining <= 0:
                return result
            try:
                await asyncio.wait_for(event.wait(), timeout=min(remaining, 2.0))
            except asyncio.TimeoutError:
                pass


@router.get("/api/clusters/{cluster_id}/history")
def history(cluster_id: int, range: str = Query("24h", pattern="^(1h|6h|24h|7d)$"), _: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict:
    get_cluster(db, cluster_id)
    hours = {"1h": 1, "6h": 6, "24h": 24, "7d": 168}[range]
    until = datetime.now(timezone.utc)
    since = until - timedelta(hours=hours)
    rows = db.scalars(select(ClusterSample).where(ClusterSample.cluster_id == cluster_id, ClusterSample.ts >= since).order_by(ClusterSample.ts)).all()
    keys = ("nodes_ready", "nodes_total", "pods_running", "pods_total", "pods_failing", "cpu_m", "cpu_alloc_m", "mem_mib", "mem_alloc_mib")
    return {"hours": hours, "samples": len(rows), "points": bucketize([(r.ts, {k: getattr(r, k) for k in keys}) for r in rows], since, until)}
