"""audit log, agent token rotation state, last agent address, join-link creator"""
from alembic import op
import sqlalchemy as sa

from app.crypto import EncryptedText

revision = "0017_audit_token_hygiene"
down_revision = "0016_user_roles_profiles"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor", sa.String(length=320), nullable=False),
        sa.Column("actor_role", sa.String(length=20), nullable=True),
        sa.Column("action", sa.String(length=60), nullable=False),
        sa.Column("target", sa.String(length=200), nullable=False),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("ip", sa.String(length=64), nullable=True),
        sa.Column("success", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.create_index("ix_audit_events_ts", "audit_events", ["ts"])
    op.create_index("ix_audit_events_action", "audit_events", ["action"])
    op.add_column("servers", sa.Column("last_agent_ip", sa.String(length=64), nullable=True))
    op.add_column("servers", sa.Column("token_issued_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("servers", sa.Column("pending_token", EncryptedText(), nullable=True))
    op.add_column("servers", sa.Column("pending_token_hash", sa.String(length=64), nullable=True))
    op.add_column("servers", sa.Column("pending_token_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_servers_pending_token_hash", "servers", ["pending_token_hash"])
    op.add_column("enrollments", sa.Column("created_by", sa.String(length=320), nullable=True))


def downgrade():
    op.drop_column("enrollments", "created_by")
    op.drop_index("ix_servers_pending_token_hash", table_name="servers")
    for column in ("pending_token_at", "pending_token_hash", "pending_token", "token_issued_at", "last_agent_ip"):
        op.drop_column("servers", column)
    op.drop_table("audit_events")
