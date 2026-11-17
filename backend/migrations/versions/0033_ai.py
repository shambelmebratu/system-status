"""AI: incident explanations, and statistical anomaly detection"""
from alembic import op
import sqlalchemy as sa

revision = "0033_ai"
down_revision = "0032_security"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("incidents", sa.Column("ai_analysis", sa.Text(), nullable=True))
    op.add_column("incidents", sa.Column("ai_model", sa.String(60), nullable=True))
    op.add_column("incidents", sa.Column("ai_generated_at", sa.DateTime(timezone=True), nullable=True))
    op.create_table("anomalies",
        sa.Column("id", sa.Integer(), primary_key=True), sa.Column("target_type", sa.String(20), nullable=False), sa.Column("target_id", sa.Integer(), nullable=False),
        sa.Column("target_name", sa.String(100), nullable=False, server_default=""), sa.Column("metric", sa.String(30), nullable=False), sa.Column("direction", sa.String(5), nullable=False),
        sa.Column("value", sa.Float(), nullable=False), sa.Column("peak", sa.Float(), nullable=False), sa.Column("baseline", sa.Float(), nullable=False),
        sa.Column("spread", sa.Float(), nullable=False), sa.Column("score", sa.Float(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()), sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("resolved_at", sa.DateTime(timezone=True)), sa.Column("alerted", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.create_index("ix_anomalies_open", "anomalies", ["target_type", "target_id", "metric", "resolved_at"])
    op.create_index("ix_anomalies_started", "anomalies", ["started_at"])


def downgrade():
    op.drop_index("ix_anomalies_started", table_name="anomalies")
    op.drop_index("ix_anomalies_open", table_name="anomalies")
    op.drop_table("anomalies")
    for column in ("ai_generated_at", "ai_model", "ai_analysis"):
        op.drop_column("incidents", column)
