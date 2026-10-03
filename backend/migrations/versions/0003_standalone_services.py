"""allow services without a server"""
from alembic import op
import sqlalchemy as sa

revision = "0003_standalone_services"
down_revision = "0002_server_observability"
branch_labels = None
depends_on = None


def upgrade():
    op.drop_constraint("services_server_id_fkey", "services", type_="foreignkey")
    op.alter_column("services", "server_id", existing_type=sa.Integer(), nullable=True)
    op.create_foreign_key("services_server_id_fkey", "services", "servers", ["server_id"], ["id"], ondelete="SET NULL")


def downgrade():
    op.drop_constraint("services_server_id_fkey", "services", type_="foreignkey")
    op.alter_column("services", "server_id", existing_type=sa.Integer(), nullable=False)
    op.create_foreign_key("services_server_id_fkey", "services", "servers", ["server_id"], ["id"], ondelete="CASCADE")