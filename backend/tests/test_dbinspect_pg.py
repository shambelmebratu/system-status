"""The Database section against a REAL PostgreSQL (embedded via the test-only `pgserver` package; skipped when it is not installed)."""
import os
import sys
import tempfile

os.environ.setdefault("ENVIRONMENT", "test"); os.environ.setdefault("JWT_SECRET", "x" * 40); os.environ.setdefault("DATABASE_URL", "sqlite://")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest

pgserver = pytest.importorskip("pgserver")
import psycopg  # noqa: E402

from app import dbinspect  # noqa: E402


@pytest.fixture(scope="module")
def pg():
    srv = pgserver.get_server(tempfile.mkdtemp(), cleanup_mode="stop")
    uri = srv.get_uri()
    with psycopg.connect(uri, autocommit=True) as c:
        c.execute('''
        CREATE TABLE customers (id serial PRIMARY KEY, email text NOT NULL UNIQUE, full_name text, country char(2), password_hash text);
        CREATE TABLE orders (id bigserial PRIMARY KEY, customer_id int REFERENCES customers(id), status text NOT NULL, total numeric(10,2));
        CREATE TABLE order_items (order_id bigint REFERENCES orders(id), line int, qty int, PRIMARY KEY (order_id, line));
        CREATE TABLE audit_dump (msg text);
        CREATE SCHEMA billing; CREATE TABLE billing.invoices (id int PRIMARY KEY, order_id bigint REFERENCES public.orders(id), "odd ""name""" text);
        INSERT INTO customers (email, full_name, country, password_hash) SELECT 'u'||g||'@x.io', CASE WHEN g%3=0 THEN NULL ELSE 'User '||g END, (ARRAY['ET','KE','US'])[g%3+1], 'h'||g FROM generate_series(1,300) g;
        INSERT INTO orders (customer_id, status, total) SELECT (g%300)+1, (ARRAY['paid','shipped'])[g%2+1], g%50 FROM generate_series(1,900) g;
        INSERT INTO orders (customer_id, status, total) VALUES (NULL, 'paid', 1);
        INSERT INTO audit_dump SELECT 'x' FROM generate_series(1,5);
        INSERT INTO billing.invoices VALUES (1, 1, 'a');
        ''')
    host = [p.split("=", 1)[1] for p in uri.split("?", 1)[1].split("&") if p.startswith("host=")][0]
    yield host
    srv.cleanup()


def test_schema_report_and_read_only(pg, monkeypatch):
    monkeypatch.setattr(dbinspect, "resolve_checked", lambda host: None)        # unix socket
    with dbinspect.PostgresInspector(pg, 5432, "postgres", "postgres", "", "disable") as insp:
        tables, rels = insp.schema()
        by = {t.key: t for t in tables}
        assert {"public.customers", "public.orders", "public.order_items", "billing.invoices"} <= set(by)
        assert [c.name for c in by["public.order_items"].columns if c.pk] == ["order_id", "line"]
        assert {(r.from_table, r.to_table) for r in rels} == {("public.orders", "public.customers"), ("public.order_items", "public.orders"), ("billing.invoices", "public.orders")}
        with pytest.raises(Exception, match="read-only"):
            insp.rows("CREATE TABLE nope (a int)")
        rep = dbinspect.build_report(insp, tables, rels, [{"table": "public.customers"}, {"table": "public.orders"}, {"table": "public.audit_dump"}, {"table": "billing.invoices"}], sample_rows=2)
        sec = {s["table"]: s for s in rep["tables"]}
        cust = {c["name"]: c for c in sec["public.customers"]["profile"]["columns"]}
        assert sec["public.customers"]["profile"]["rows"] == 300 and cust["full_name"]["null_pct"] == 33.3 and cust["country"]["distinct"] == 3
        assert "min" not in cust["password_hash"] and "top" not in cust["password_hash"] and all(row[4] == "•••" for row in sec["public.customers"]["profile"]["sample"])
        assert "Each order may belong to one customer" in rep["relations"][0]["text"] or any("Each order may belong" in r["text"] for r in rep["relations"])
        assert any("no primary key" in q for q in sec["public.audit_dump"]["quality"])
        assert any("missing in 1 row." in q for q in sec["public.orders"]["quality"])
        assert sec["billing.invoices"]["profile"]["columns"][2]["name"] == 'odd "name"' and "error" not in sec["billing.invoices"]["profile"]["columns"][2]
        for bad in ([{"table": "public.customers; DROP TABLE x"}], [{"table": "public.customers", "columns": ['id"; drop']}]):
            with pytest.raises(dbinspect.DbError):
                dbinspect.build_report(insp, tables, rels, bad)
