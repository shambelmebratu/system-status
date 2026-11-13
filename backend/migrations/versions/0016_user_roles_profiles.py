"""user profiles, roles management, account disabling and forced password change"""
from alembic import op
import sqlalchemy as sa

revision = "0016_user_roles_profiles"
down_revision = "0015_log_requests"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("users", sa.Column("name", sa.String(length=100), nullable=False, server_default=""))
    op.add_column("users", sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()))
    op.add_column("users", sa.Column("must_change_password", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("users", sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True))
    # Every account that existed before roles were introduced was a full administrator: keep it that way.
    op.execute("UPDATE users SET role = 'admin' WHERE role IS NULL OR role NOT IN ('admin', 'operator', 'viewer')")


def downgrade():
    for column in ("last_login_at", "must_change_password", "active", "name"):
        op.drop_column("users", column)
