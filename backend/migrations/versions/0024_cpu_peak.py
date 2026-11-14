"""highest CPU between two agent reports, so graphs can show spikes the average hides"""
from alembic import op
import sqlalchemy as sa

revision = "0024_cpu_peak"
down_revision = "0023_perf_targets"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("metric_samples", sa.Column("cpu_peak", sa.Float(), nullable=True))


def downgrade():
    op.drop_column("metric_samples", "cpu_peak")
