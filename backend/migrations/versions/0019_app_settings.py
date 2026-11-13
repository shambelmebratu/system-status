"""admin-editable settings (data retention and purge schedule)"""
from alembic import op
import sqlalchemy as sa

revision = "0019_app_settings"
down_revision = "0018_log_policy_k8s"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "app_settings",
        sa.Column("key", sa.String(length=60), primary_key=True),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.String(length=320), nullable=True),
    )


def downgrade():
    op.drop_table("app_settings")
