"""persist latest HTTP response code for service checks"""
from alembic import op
import sqlalchemy as sa

revision = "0004_service_http_status"
down_revision = "0003_standalone_services"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("services", sa.Column("last_http_status", sa.Integer(), nullable=True))


def downgrade():
    op.drop_column("services", "last_http_status")