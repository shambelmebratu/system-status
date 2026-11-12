"""add session revocation counter and encrypt stored secrets"""
from alembic import op
import sqlalchemy as sa

from app.crypto import PREFIX, encrypt

revision = "0009_security_hardening"
down_revision = "0008_notification_providers"
branch_labels = None
depends_on = None

SECRET_COLUMNS = (("servers", "agent_token"), ("channels", "token"), ("channels", "endpoint"))


def upgrade():
    op.add_column("users", sa.Column("token_version", sa.Integer(), nullable=False, server_default="0"))
    bind = op.get_bind()
    for table, column in SECRET_COLUMNS:
        rows = bind.execute(sa.text(f"SELECT id, {column} FROM {table} WHERE {column} IS NOT NULL AND {column} <> ''")).all()
        for row_id, value in rows:
            if not value.startswith(PREFIX):
                bind.execute(sa.text(f"UPDATE {table} SET {column} = :v WHERE id = :i"), {"v": encrypt(value), "i": row_id})


def downgrade():
    # Secrets stay encrypted; the application can still read them via the EncryptedText type.
    op.drop_column("users", "token_version")
