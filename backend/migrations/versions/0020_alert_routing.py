"""alert routing: which kinds of alerts each channel receives"""
from alembic import op
import sqlalchemy as sa

revision = "0020_alert_routing"
down_revision = "0019_app_settings"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("channels", sa.Column("notify_kinds", sa.String(length=100), nullable=True))
    op.add_column("channels", sa.Column("notify_events", sa.String(length=100), nullable=True))
    op.add_column("alert_events", sa.Column("state", sa.String(length=20), nullable=True))


def downgrade():
    op.drop_column("alert_events", "state")
    op.drop_column("channels", "notify_events")
    op.drop_column("channels", "notify_kinds")
