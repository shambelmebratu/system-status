"""indexes for dashboard queries that look at every target over a time window (and for the retention purge)

On PostgreSQL they are built CONCURRENTLY: monitoring keeps writing while a large history table is indexed."""
from alembic import op

revision = "0028_performance_indexes"
down_revision = "0027_db_connections"
branch_labels = None
depends_on = None

INDEXES = [
    ("ix_check_results_checked_at", "check_results", ["checked_at"]),
    ("ix_metric_samples_ts", "metric_samples", ["ts"]),
    ("ix_traffic_samples_ts", "traffic_samples", ["ts"]),
    ("ix_alert_events_created_at", "alert_events", ["created_at"]),
    ("ix_alert_events_target", "alert_events", ["target_type", "target_id", "id"]),
]


def upgrade():
    if op.get_bind().dialect.name == "postgresql":
        with op.get_context().autocommit_block():
            for name, table, columns in INDEXES:
                op.create_index(name, table, columns, postgresql_concurrently=True, if_not_exists=True)
            op.execute("ANALYZE check_results; ANALYZE metric_samples; ANALYZE alert_events")
    else:
        for name, table, columns in INDEXES:
            op.create_index(name, table, columns, if_not_exists=True)


def downgrade():
    if op.get_bind().dialect.name == "postgresql":
        with op.get_context().autocommit_block():
            for name, table, _ in INDEXES:
                op.drop_index(name, table_name=table, postgresql_concurrently=True, if_exists=True)
    else:
        for name, table, _ in INDEXES:
            op.drop_index(name, table_name=table, if_exists=True)
