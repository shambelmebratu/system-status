"""allow servers on the public status page"""
from alembic import op
import sqlalchemy as sa

revision = "0012_server_public_flag"
down_revision = "0011_failure_debounce"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("servers", sa.Column("public", sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade():
    op.drop_column("servers", "public")
