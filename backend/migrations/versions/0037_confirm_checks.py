"""Servers and services: how many failed checks in a row before an alert (NULL = ALERT_AFTER_FAILURES)"""
from alembic import op
import sqlalchemy as sa

revision = "0037_confirm_checks"
down_revision = "0036_ssh_detail"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("servers", sa.Column("confirm_checks", sa.Integer(), nullable=True))
    op.add_column("services", sa.Column("confirm_checks", sa.Integer(), nullable=True))


def downgrade():
    op.drop_column("services", "confirm_checks")
    op.drop_column("servers", "confirm_checks")
