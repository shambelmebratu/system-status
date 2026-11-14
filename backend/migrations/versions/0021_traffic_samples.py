"""real-traffic response-time summaries reported by agents"""
from alembic import op
import sqlalchemy as sa

revision = "0021_traffic_samples"
down_revision = "0020_alert_routing"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "traffic_samples",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("server_id", sa.Integer(), sa.ForeignKey("servers.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_seconds", sa.Float(), nullable=False),
        sa.Column("requests", sa.Integer(), nullable=False),
        sa.Column("errors_5xx", sa.Integer(), nullable=False),
        sa.Column("errors_4xx", sa.Integer(), nullable=False),
        sa.Column("sum_ms", sa.Float(), nullable=False),
        sa.Column("max_ms", sa.Float(), nullable=False),
        sa.Column("upstream_sum_ms", sa.Float(), nullable=False),
        sa.Column("upstream_count", sa.Integer(), nullable=False),
        sa.Column("bounds", sa.Text(), nullable=False),
        sa.Column("counts", sa.Text(), nullable=False),
    )
    op.create_index("ix_traffic_samples_server_time", "traffic_samples", ["server_id", "ts"])


def downgrade():
    op.drop_index("ix_traffic_samples_server_time", table_name="traffic_samples")
    op.drop_table("traffic_samples")
