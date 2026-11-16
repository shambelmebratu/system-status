"""Database section: MongoDB connections (the database the user is defined in)"""
from alembic import op
import sqlalchemy as sa

revision = "0029_db_auth_source"
down_revision = "0028_performance_indexes"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("db_connections", sa.Column("auth_source", sa.String(64), nullable=True))


def downgrade():
    op.drop_column("db_connections", "auth_source")
