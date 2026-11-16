"""service request timeout and TLS certificate expiry check"""
from alembic import op
import sqlalchemy as sa

revision = "0026_service_timeout_cert"
down_revision = "0025_user_access_scope"
branch_labels = None
depends_on = None

COLUMNS = [
    sa.Column("timeout_seconds", sa.Integer(), nullable=True),
    sa.Column("cert_check", sa.Boolean(), nullable=False, server_default=sa.true()),
    sa.Column("cert_alert_days", sa.String(60), nullable=True),
    sa.Column("cert_expires_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("cert_issuer", sa.String(200), nullable=True),
    sa.Column("cert_subject", sa.String(300), nullable=True),
    sa.Column("cert_checked_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("cert_error", sa.Text(), nullable=True),
    sa.Column("cert_alerted", sa.Integer(), nullable=True),
]


def upgrade():
    for column in COLUMNS:
        op.add_column("services", column)


def downgrade():
    for column in reversed(COLUMNS):
        op.drop_column("services", column.name)
