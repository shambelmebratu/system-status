"""Security: successful SSH logins (with suspicious ones flagged) and threat findings (malware, persistence, new SSH keys)"""
from alembic import op
import sqlalchemy as sa

revision = "0034_threats"
down_revision = "0033_ai"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("ssh_login_events",
        sa.Column("id", sa.Integer(), primary_key=True), sa.Column("server_id", sa.Integer(), sa.ForeignKey("servers.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()), sa.Column("ip", sa.String(45), nullable=False),
        sa.Column("user", sa.String(64), nullable=False, server_default=""), sa.Column("method", sa.String(30), nullable=False, server_default=""),
        sa.Column("failures_before", sa.Integer(), nullable=False, server_default="0"), sa.Column("new_source", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.create_index("ix_ssh_logins_server_ip", "ssh_login_events", ["server_id", "ip"])
    op.create_index("ix_ssh_logins_time", "ssh_login_events", ["ts"])
    op.create_table("security_findings",
        sa.Column("id", sa.Integer(), primary_key=True), sa.Column("server_id", sa.Integer(), sa.ForeignKey("servers.id", ondelete="CASCADE"), nullable=False),
        sa.Column("key", sa.String(200), nullable=False), sa.Column("source", sa.String(10), nullable=False, server_default="agent"), sa.Column("kind", sa.String(40), nullable=False),
        sa.Column("severity", sa.String(10), nullable=False), sa.Column("title", sa.String(200), nullable=False), sa.Column("detail", sa.Text(), nullable=False, server_default=""),
        sa.Column("evidence", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()), sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("resolved_at", sa.DateTime(timezone=True)), sa.Column("acknowledged_by", sa.String(320)), sa.Column("acknowledged_at", sa.DateTime(timezone=True)),
        sa.Column("note", sa.Text(), nullable=False, server_default=""))
    op.create_index("ix_findings_server_key", "security_findings", ["server_id", "key", "resolved_at"])
    op.create_index("ix_findings_open", "security_findings", ["resolved_at", "severity"])


def downgrade():
    op.drop_index("ix_findings_open", table_name="security_findings")
    op.drop_index("ix_findings_server_key", table_name="security_findings")
    op.drop_table("security_findings")
    op.drop_index("ix_ssh_logins_time", table_name="ssh_login_events")
    op.drop_index("ix_ssh_logins_server_ip", table_name="ssh_login_events")
    op.drop_table("ssh_login_events")
