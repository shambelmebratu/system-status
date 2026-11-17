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
        assert any("No primary key" in q["text"] for q in sec["public.audit_dump"]["quality"])
        assert any("Link missing in 1 row." in q["text"] for q in sec["public.orders"]["quality"])
        assert sec["billing.invoices"]["profile"]["columns"][2]["name"] == 'odd "name"' and "error" not in sec["billing.invoices"]["profile"]["columns"][2]
        for bad in ([{"table": "public.customers; DROP TABLE x"}], [{"table": "public.customers", "columns": ['id"; drop']}]):
            with pytest.raises(dbinspect.DbError):
                dbinspect.build_report(insp, tables, rels, bad)


def test_quick_queries(pg, monkeypatch):
    from app import dbquery
    monkeypatch.setattr(dbinspect, "resolve_checked", lambda host: None)
    with dbinspect.PostgresInspector(pg, 5432, "postgres", "postgres", "", "disable") as insp:
        tables, _ = insp.schema()
        by = {t.key: t for t in tables}
        orders, customers = by["public.orders"], by["public.customers"]
        r = dbquery.run(insp, orders, {"measures": [{"fn": "count"}, {"fn": "sum", "column": "total"}, {"fn": "avg", "column": "total"}, {"fn": "min", "column": "total"}, {"fn": "max", "column": "total"}]})
        assert r["columns"] == ["count(*)", "sum(total)", "avg(total)", "min(total)", "max(total)"] and r["rows"][0][0] == 901 and r["rows"][0][3] == 0 and r["rows"][0][4] == 49
        g = dbquery.run(insp, orders, {"measures": [{"fn": "count"}], "group_by": [{"column": "status"}], "order": "group_asc"})
        assert g["rows"] == [["paid", 451], ["shipped", 450]] and g["groups"] == 1 and "GROUP BY" in g["query"]
        f = dbquery.run(insp, orders, {"measures": [{"fn": "count"}], "filters": [{"column": "total", "op": "gte", "value": "40"}, {"column": "status", "op": "eq", "value": "paid"}]})
        assert f["rows"][0][0] == 90 and "'paid'" in f["query"]
        c = dbquery.run(insp, customers, {"measures": [{"fn": "count_distinct", "column": "country"}, {"fn": "count", "column": "full_name"}], "filters": [{"column": "email", "op": "contains", "value": "u1"}]})
        assert c["rows"][0][0] == 3 and c["rows"][0][1] < 300
        assert dbquery.run(insp, customers, {"measures": [{"fn": "count", "column": "password_hash"}]})["rows"][0][0] == 300   # sensitive: counting is allowed
        nul = dbquery.run(insp, orders, {"measures": [{"fn": "count"}], "filters": [{"column": "customer_id", "op": "is_null"}]})
        assert nul["rows"][0][0] == 1
        inn = dbquery.run(insp, orders, {"measures": [{"fn": "count"}], "filters": [{"column": "total", "op": "in", "value": "1, 2,3"}]})
        assert inn["rows"][0][0] > 0
        for bad, msg in (({"measures": [{"fn": "max", "column": "password_hash"}]}, "sensitive"), ({"measures": [{"fn": "count"}], "group_by": [{"column": "password_hash"}]}, "sensitive"),
                         ({"measures": [{"fn": "sum", "column": "email"}]}, "number"), ({"measures": [{"fn": "count"}], "filters": [{"column": "id", "op": "gt", "value": "1 OR 1=1"}]}, "not a number"),
                         ({"measures": [{"fn": "count", "column": 'id"; drop table x; --'}]}, "Unknown"), ({"measures": [{"fn": "count"}], "group_by": [{"column": "status", "bucket": "month"}]}, "not a date")):
            with pytest.raises(dbinspect.DbError, match=msg):
                dbquery.run(insp, by["public.customers" if "password" in str(bad) or "email" in str(bad) else "public.orders"], bad)
        quote = dbquery.run(insp, orders, {"measures": [{"fn": "count"}], "filters": [{"column": "status", "op": "eq", "value": "x' OR '1'='1"}]})
        assert quote["rows"][0][0] == 0                                               # a value is only ever a bound parameter


def test_quick_query_by_month(pg, monkeypatch):
    from app import dbquery
    with psycopg.connect(host=pg, dbname="postgres", user="postgres", autocommit=True) as c:
        c.execute("CREATE TABLE IF NOT EXISTS events (id serial PRIMARY KEY, at timestamptz NOT NULL, amount int); TRUNCATE events;"
                  "INSERT INTO events (at, amount) SELECT timestamptz '2026-01-15' + (g || ' days')::interval, g FROM generate_series(0, 59) g;")
    monkeypatch.setattr(dbinspect, "resolve_checked", lambda host: None)
    with dbinspect.PostgresInspector(pg, 5432, "postgres", "postgres", "", "disable") as insp:
        tables, _ = insp.schema()
        events = next(t for t in tables if t.key == "public.events")
        r = dbquery.run(insp, events, {"measures": [{"fn": "count"}, {"fn": "sum", "column": "amount"}], "group_by": [{"column": "at", "bucket": "month"}], "order": "group_asc"})
        assert [row[0] for row in r["rows"]] == ["2026-01", "2026-02", "2026-03"] and sum(row[1] for row in r["rows"]) == 60
