"""check history, metric samples, incidents, push-mode agents, public status flag"""
import hashlib

from alembic import op
import sqlalchemy as sa

from app.crypto import decrypt

revision = "0010_history_incidents_push"
down_revision = "0009_security_hardening"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("servers", sa.Column("token_hash", sa.String(length=64), nullable=True))
    op.add_column("servers", sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_servers_token_hash", "servers", ["token_hash"])
    op.add_column("services", sa.Column("public", sa.Boolean(), nullable=False, server_default=sa.false()))

    op.create_table(
        "check_results",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_type", sa.String(length=20), nullable=False),
        sa.Column("target_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("latency_ms", sa.Float(), nullable=True),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_check_results_target_time", "check_results", ["target_type", "target_id", "checked_at"])
    op.create_table(
        "metric_samples",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("server_id", sa.Integer(), sa.ForeignKey("servers.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("cpu", sa.Float(), nullable=False),
        sa.Column("memory", sa.Float(), nullable=False),
        sa.Column("disk", sa.Float(), nullable=False),
        sa.Column("load", sa.Float(), nullable=False),
        sa.Column("swap", sa.Float(), nullable=False),
        sa.Column("net_rx_bps", sa.Float(), nullable=True),
        sa.Column("net_tx_bps", sa.Float(), nullable=True),
    )
    op.create_index("ix_metric_samples_server_time", "metric_samples", ["server_id", "ts"])
    op.create_table(
        "incidents",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_type", sa.String(length=20), nullable=False),
        sa.Column("target_id", sa.Integer(), nullable=False),
        sa.Column("target_name", sa.String(length=100), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_incidents_target", "incidents", ["target_type", "target_id", "resolved_at"])
    op.create_index("ix_incidents_started_at", "incidents", ["started_at"])

    # Backfill the lookup hash for existing agent tokens (stored encrypted since 0009).
    bind = op.get_bind()
    for row_id, token in bind.execute(sa.text("SELECT id, agent_token FROM servers WHERE agent_token IS NOT NULL AND agent_token <> ''")).all():
        digest = hashlib.sha256(decrypt(token).encode()).hexdigest()
        bind.execute(sa.text("UPDATE servers SET token_hash = :h WHERE id = :i"), {"h": digest, "i": row_id})


def downgrade():
    op.drop_table("incidents")
    op.drop_table("metric_samples")
    op.drop_table("check_results")
    op.drop_column("services", "public")
    op.drop_index("ix_servers_token_hash", table_name="servers")
    op.drop_column("servers", "last_seen_at")
    op.drop_column("servers", "token_hash")
