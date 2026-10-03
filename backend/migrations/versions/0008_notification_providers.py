"""add webhook slack and WhatsApp notification channel settings"""
from alembic import op
import sqlalchemy as sa

revision = "0008_notification_providers"
down_revision = "0007_server_check_interval"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("channels", sa.Column("endpoint", sa.Text(), nullable=True))
    op.add_column("channels", sa.Column("phone_number_id", sa.String(length=100), nullable=True))
    op.add_column("channels", sa.Column("template_name", sa.String(length=100), nullable=True))
    op.add_column("channels", sa.Column("template_language", sa.String(length=20), nullable=True, server_default="en_US"))


def downgrade():
    op.drop_column("channels", "template_language")
    op.drop_column("channels", "template_name")
    op.drop_column("channels", "phone_number_id")
    op.drop_column("channels", "endpoint")