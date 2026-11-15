"""per-user access scope: which servers, services and clusters a non-admin may see (NULL = everything)"""
from alembic import op
import sqlalchemy as sa

revision = "0025_user_access_scope"
down_revision = "0024_cpu_peak"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("users", sa.Column("access_scope", sa.Text(), nullable=True))


def downgrade():
    op.drop_column("users", "access_scope")
