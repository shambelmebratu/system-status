"""Security: two-factor sign-in, SSH brute-force samples, exposure scans and TLS audits"""
from alembic import op
import sqlalchemy as sa

revision = "0032_security"
down_revision = "0031_devops"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("users", sa.Column("totp_secret", sa.Text(), nullable=True))
    op.add_column("users", sa.Column("totp_enabled", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("users", sa.Column("totp_last_step", sa.Integer(), nullable=True))
    op.add_column("users", sa.Column("recovery_codes", sa.Text(), nullable=True))
    op.add_column("servers", sa.Column("ssh_alert_at", sa.DateTime(timezone=True), nullable=True))
    op.create_table("ssh_failure_samples",
        sa.Column("id", sa.Integer(), primary_key=True), sa.Column("server_id", sa.Integer(), sa.ForeignKey("servers.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()), sa.Column("total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("ips", sa.Text(), nullable=False, server_default="{}"), sa.Column("users", sa.Text(), nullable=False, server_default="{}"))
    op.create_index("ix_ssh_failures_server_time", "ssh_failure_samples", ["server_id", "ts"])
    op.create_index("ix_ssh_failures_time", "ssh_failure_samples", ["ts"])
    op.create_table("security_scans",
        sa.Column("id", sa.Integer(), primary_key=True), sa.Column("kind", sa.String(10), nullable=False), sa.Column("target_type", sa.String(20), nullable=False),
        sa.Column("target_id", sa.Integer(), nullable=False), sa.Column("address", sa.String(300), nullable=False, server_default=""),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()), sa.Column("duration_ms", sa.Float(), nullable=False, server_default="0"),
        sa.Column("grade", sa.String(4)), sa.Column("findings", sa.Integer(), nullable=False, server_default="0"), sa.Column("results", sa.Text(), nullable=False, server_default="{}"), sa.Column("error", sa.Text()))
    op.create_index("ix_security_scans_target", "security_scans", ["kind", "target_type", "target_id", "started_at"])


def downgrade():
    op.drop_index("ix_security_scans_target", table_name="security_scans")
    op.drop_table("security_scans")
    op.drop_index("ix_ssh_failures_time", table_name="ssh_failure_samples")
    op.drop_index("ix_ssh_failures_server_time", table_name="ssh_failure_samples")
    op.drop_table("ssh_failure_samples")
    op.drop_column("servers", "ssh_alert_at")
    for column in ("recovery_codes", "totp_last_step", "totp_enabled", "totp_secret"):
        op.drop_column("users", column)
