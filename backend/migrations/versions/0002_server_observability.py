"""add host reachability and process monitoring"""
from alembic import op
import sqlalchemy as sa

revision = "0002_server_observability"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("servers", sa.Column("host", sa.String(255), nullable=False, server_default=""))
    op.add_column("servers", sa.Column("process_names", sa.Text, nullable=False, server_default=""))
    op.add_column("servers", sa.Column("process_threshold", sa.Float, nullable=False, server_default="80"))
    op.add_column("servers", sa.Column("last_metrics", sa.Text))


def downgrade():
    op.drop_column("servers", "last_metrics")
    op.drop_column("servers", "process_threshold")
    op.drop_column("servers", "process_names")
    op.drop_column("servers", "host")