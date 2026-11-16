"""Database section: connections (read-only) and saved report definitions"""
from alembic import op
import sqlalchemy as sa

revision = "0027_db_connections"
down_revision = "0026_service_timeout_cert"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "db_connections",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("engine", sa.String(20), nullable=False),
        sa.Column("host", sa.String(255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("database", sa.String(128), nullable=False),
        sa.Column("username", sa.String(128), nullable=False),
        sa.Column("password", sa.Text(), nullable=True),
        sa.Column("ssl_mode", sa.String(20), nullable=False, server_default="prefer"),
        sa.Column("schemas", sa.String(500), nullable=True),
        sa.Column("created_by", sa.String(320), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_ok_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("server_version", sa.String(60), nullable=True),
    )
    op.create_table(
        "db_reports",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("connection_id", sa.Integer(), sa.ForeignKey("db_connections.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("selection", sa.Text(), nullable=False),
        sa.Column("sample_rows", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_by", sa.String(320), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )


def downgrade():
    op.drop_table("db_reports")
    op.drop_table("db_connections")
