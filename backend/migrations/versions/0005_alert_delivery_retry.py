"""track and retry alert delivery failures"""
from alembic import op
import sqlalchemy as sa

revision = "0005_alert_delivery_retry"
down_revision = "0004_service_http_status"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("alert_events", sa.Column("delivery_error", sa.Text(), nullable=True))
    op.add_column("alert_events", sa.Column("delivery_attempts", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("alert_events", sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True))
    # Do not unexpectedly replay historical notifications after this migration.
    op.execute("UPDATE alert_events SET delivery_attempts = 10 WHERE sent = false")


def downgrade():
    op.drop_column("alert_events", "last_attempt_at")
    op.drop_column("alert_events", "delivery_attempts")
    op.drop_column("alert_events", "delivery_error")