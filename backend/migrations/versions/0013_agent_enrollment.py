"""join tokens (agent self-registration) and stable machine ids"""
from alembic import op
import sqlalchemy as sa

revision = "0013_agent_enrollment"
down_revision = "0012_server_public_flag"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("servers", sa.Column("machine_id", sa.String(length=64), nullable=True))
    op.create_index("ix_servers_machine_id", "servers", ["machine_id"])
    op.create_table(
        "enrollments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("label", sa.String(length=100), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("token", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("max_uses", sa.Integer(), nullable=True),
        sa.Column("uses", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_enrollments_token_hash", "enrollments", ["token_hash"], unique=True)


def downgrade():
    op.drop_table("enrollments")
    op.drop_index("ix_servers_machine_id", table_name="servers")
    op.drop_column("servers", "machine_id")
