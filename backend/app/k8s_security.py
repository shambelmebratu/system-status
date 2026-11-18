"""Kubernetes security findings: applies the cluster agent's security checks to the database and alerts on new serious ones.

One row per (cluster, key); the key names the rule and the workload, so the same problem seen in every report stays one finding.
Findings the agent no longer reports are resolved. New critical/high findings alert once (threshold: THREAT_ALERT_SEVERITY)."""
from __future__ import annotations

import json
from datetime import datetime

from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from .threats import SEVERITY_ORDER, _alert_level, aware

EVIDENCE_KEYS = ("container", "image", "command", "path", "capabilities", "subject", "role", "pods", "created")


def _printable(value: str) -> str:
    return " ".join("".join(ch if ch.isprintable() else " " for ch in value).split())


class K8sFinding(BaseModel):
    key: str = Field(min_length=1, max_length=300)
    kind: str = Field(pattern=r"^k8s_[a-z_]{1,36}$")
    severity: str = Field(pattern="^(critical|high|medium|low)$")
    title: str = Field(max_length=200)
    detail: str = Field(default="", max_length=1000)
    namespace: str = Field(default="", max_length=253)
    object: str = Field(default="", max_length=300)
    container: str = Field(default="", max_length=253)
    image: str = Field(default="", max_length=300)
    command: str = Field(default="", max_length=300)
    path: str = Field(default="", max_length=300)
    capabilities: str = Field(default="", max_length=300)
    subject: str = Field(default="", max_length=300)
    role: str = Field(default="", max_length=300)
    pods: int | None = Field(default=None, ge=0, le=1_000_000)
    created: str | None = Field(default=None, max_length=40)

    @field_validator("key", "title", "detail", "namespace", "object", "container", "image", "command", "path", "capabilities", "subject", "role")
    @classmethod
    def printable(cls, v: str) -> str:   # names come from the cluster: no control characters in the dashboard, alerts or audit log
        return _printable(v)


class K8sSecurity(BaseModel):
    checked_at: str | None = Field(default=None, max_length=40)
    findings: list[K8sFinding] = Field(default_factory=list, max_length=300)
    rbac_checked: bool = False
    rbac_error: str | None = Field(default=None, max_length=300)


def sync_cluster_findings(db: Session, cluster, report: K8sSecurity, now: datetime) -> list:
    """Opens, refreshes and resolves findings. Returns the new ones that should alert."""
    from .models import ClusterFinding
    level = _alert_level()
    open_rows = {r.key: r for r in db.scalars(select(ClusterFinding).where(ClusterFinding.cluster_id == cluster.id, ClusterFinding.resolved_at.is_(None))).all()}
    seen, new_serious = set(), []
    for f in report.findings:
        seen.add(f.key)
        evidence = json.dumps({k: getattr(f, k) for k in EVIDENCE_KEYS if getattr(f, k) not in (None, "")})
        row = open_rows.get(f.key)
        if row:
            row.last_seen, row.severity, row.title, row.detail, row.evidence = now, f.severity, f.title, f.detail, evidence
            continue
        row = ClusterFinding(cluster_id=cluster.id, key=f.key, kind=f.kind, severity=f.severity, namespace=f.namespace, object=f.object, title=f.title, detail=f.detail,
                             evidence=evidence, first_seen=now, last_seen=now)
        db.add(row)
        if SEVERITY_ORDER[f.severity] <= level:
            new_serious.append(row)
    for key, row in open_rows.items():
        if key not in seen and not (key.startswith("rbac_") and not report.rbac_checked):   # an RBAC check that could not run proves nothing
            row.resolved_at = now
    db.flush()
    if new_serious:
        from .monitoring import format_alert, queue_event
        worst = "critical" if any(r.severity == "critical" for r in new_serious) else "warning"
        lines = [f"{r.title}" for r in new_serious[:6]] + ([f"… and {len(new_serious) - 6} more"] if len(new_serious) > 6 else []) + ["See Security → Kubernetes."]
        queue_event(db, "cluster", cluster, worst, format_alert("Kubernetes", "threat", cluster.name, lines), deliver=False, state="threat")
    return new_serious


def finding_view(f, cluster_info: dict | None = None) -> dict:
    return {"id": f.id, "cluster_id": f.cluster_id, "cluster": cluster_info, "key": f.key, "kind": f.kind, "severity": f.severity, "namespace": f.namespace, "object": f.object,
            "title": f.title, "detail": f.detail, "evidence": json.loads(f.evidence or "{}"), "first_seen": aware(f.first_seen).isoformat(), "last_seen": aware(f.last_seen).isoformat(),
            "resolved_at": aware(f.resolved_at).isoformat() if f.resolved_at else None, "acknowledged_by": f.acknowledged_by,
            "acknowledged_at": aware(f.acknowledged_at).isoformat() if f.acknowledged_at else None, "note": f.note}
