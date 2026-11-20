"""SSH logins: which key was used (type, fingerprint, name) and file-transfer sessions"""
from alembic import op
import sqlalchemy as sa

revision = "0036_ssh_detail"
down_revision = "0035_k8s_findings"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("ssh_login_events", sa.Column("kind", sa.String(10), nullable=False, server_default="login"))
    op.add_column("ssh_login_events", sa.Column("key_type", sa.String(30), nullable=False, server_default=""))
    op.add_column("ssh_login_events", sa.Column("fingerprint", sa.String(80), nullable=False, server_default=""))
    op.add_column("ssh_login_events", sa.Column("key_name", sa.String(80), nullable=False, server_default=""))


def downgrade():
    for column in ("key_name", "fingerprint", "key_type", "kind"):
        op.drop_column("ssh_login_events", column)
