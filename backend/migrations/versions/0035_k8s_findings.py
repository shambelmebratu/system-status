"""Kubernetes security findings (privileged / host-level workloads, risky mounts, miners, risky RBAC bindings)"""
from alembic import op
import sqlalchemy as sa

revision = "0035_k8s_findings"
down_revision = "0034_threats"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("cluster_findings",
        sa.Column("id", sa.Integer(), primary_key=True), sa.Column("cluster_id", sa.Integer(), sa.ForeignKey("clusters.id", ondelete="CASCADE"), nullable=False),
        sa.Column("key", sa.String(300), nullable=False), sa.Column("kind", sa.String(40), nullable=False), sa.Column("severity", sa.String(10), nullable=False),
        sa.Column("namespace", sa.String(253), nullable=False, server_default=""), sa.Column("object", sa.String(300), nullable=False, server_default=""),
        sa.Column("title", sa.String(200), nullable=False), sa.Column("detail", sa.Text(), nullable=False, server_default=""), sa.Column("evidence", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()), sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("resolved_at", sa.DateTime(timezone=True)), sa.Column("acknowledged_by", sa.String(320)), sa.Column("acknowledged_at", sa.DateTime(timezone=True)),
        sa.Column("note", sa.Text(), nullable=False, server_default=""))
    op.create_index("ix_cluster_findings_key", "cluster_findings", ["cluster_id", "key", "resolved_at"])
    op.create_index("ix_cluster_findings_open", "cluster_findings", ["resolved_at", "severity"])


def downgrade():
    op.drop_index("ix_cluster_findings_open", table_name="cluster_findings")
    op.drop_index("ix_cluster_findings_key", table_name="cluster_findings")
    op.drop_table("cluster_findings")
