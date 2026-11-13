"""per-server log access policy and Kubernetes cluster monitoring"""
from alembic import op
import sqlalchemy as sa

from app.crypto import EncryptedText

revision = "0018_log_policy_k8s"
down_revision = "0017_audit_token_hygiene"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("servers", sa.Column("log_policy", sa.Text(), nullable=True))
    op.create_table(
        "clusters",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("token_hash", sa.String(length=64), nullable=True),
        sa.Column("agent_token", EncryptedText(), nullable=True),
        sa.Column("token_issued_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("pending_token", EncryptedText(), nullable=True),
        sa.Column("pending_token_hash", sa.String(length=64), nullable=True),
        sa.Column("pending_token_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_agent_ip", sa.String(length=64), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(length=20), nullable=False, server_default="unknown"),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("k8s_version", sa.String(length=40), nullable=True),
        sa.Column("agent_version", sa.String(length=32), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("log_policy", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(length=320), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_clusters_name", "clusters", ["name"], unique=True)
    op.create_index("ix_clusters_token_hash", "clusters", ["token_hash"])
    op.create_index("ix_clusters_pending_token_hash", "clusters", ["pending_token_hash"])
    op.create_table(
        "cluster_samples",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("cluster_id", sa.Integer(), sa.ForeignKey("clusters.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("nodes_ready", sa.Integer(), nullable=False),
        sa.Column("nodes_total", sa.Integer(), nullable=False),
        sa.Column("pods_running", sa.Integer(), nullable=False),
        sa.Column("pods_total", sa.Integer(), nullable=False),
        sa.Column("pods_failing", sa.Integer(), nullable=False),
        sa.Column("cpu_m", sa.Float(), nullable=True),
        sa.Column("cpu_alloc_m", sa.Float(), nullable=True),
        sa.Column("mem_mib", sa.Float(), nullable=True),
        sa.Column("mem_alloc_mib", sa.Float(), nullable=True),
    )
    op.create_index("ix_cluster_samples_cluster_time", "cluster_samples", ["cluster_id", "ts"])
    op.create_table(
        "k8s_requests",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("cluster_id", sa.Integer(), sa.ForeignKey("clusters.id", ondelete="CASCADE"), nullable=False),
        sa.Column("query", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=10), nullable=False),
        sa.Column("output", sa.Text(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("truncated", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_k8s_requests_cluster_status", "k8s_requests", ["cluster_id", "status"])


def downgrade():
    op.drop_table("k8s_requests")
    op.drop_table("cluster_samples")
    op.drop_table("clusters")
    op.drop_column("servers", "log_policy")
