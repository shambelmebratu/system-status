"""The Database section on MongoDB: inferred fields and relations, profiles, masking. Runs against `mongomock` (an in-process
imitation of MongoDB; skipped when it is not installed). It does not prove every aggregation runs on a real server."""
import datetime
import os
import sys

os.environ.setdefault("ENVIRONMENT", "test"); os.environ.setdefault("JWT_SECRET", "x" * 40); os.environ.setdefault("DATABASE_URL", "sqlite://")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest

mongomock = pytest.importorskip("mongomock")
from bson import DBRef, ObjectId  # noqa: E402

from app import dbinspect, dbmongo  # noqa: E402

DROP = {"maxTimeMS", "max_time_ms", "allowDiskUse"}     # time limits real MongoDB honours and mongomock rejects


class _Coll:
    def __init__(self, c): self._c = c
    def __getattr__(self, name):
        attr = getattr(self._c, name)
        return (lambda *a, **k: attr(*a, **{x: y for x, y in k.items() if x not in DROP})) if callable(attr) else attr


class _Db:
    def __init__(self, d): self._d = d
    def __getitem__(self, name): return _Coll(self._d[name])
    def __getattr__(self, name): return getattr(self._d, name)
    def command(self, *a, **k): raise RuntimeError("collStats is not in mongomock")
    def list_collections(self): return [{"name": n, "type": "collection"} for n in self._d.list_collection_names()]


@pytest.fixture()
def insp():
    client = mongomock.MongoClient(); db = client.shop
    cust = [{"_id": ObjectId(), "email": f"u{i}@x.io", "name": {"first": f"U{i}", "last": "Doe"} if i % 4 else {"first": f"U{i}"}, "country": ["ET", "KE", "US"][i % 3],
             "password_hash": f"h{i}", "tags": ["vip"] if i % 10 == 0 else [], **({"phone": "+251900"} if i % 3 else {})} for i in range(300)]
    db.customers.insert_many(cust)
    prods = [{"_id": ObjectId(), "sku": f"SKU-{i}", "price": 9.5 + i} for i in range(40)]
    db.products.insert_many(prods)
    orders = [{"_id": ObjectId(), "customerId": cust[i % 300]["_id"], "status": ["paid", "shipped"][i % 2], "total": 10.0 + i % 50,
               "items": [{"product_id": prods[(i + k) % 40]["_id"], "qty": 1 + k} for k in range(1 + i % 2)], "placed_at": datetime.datetime(2026, 11, 1) - datetime.timedelta(hours=i)} for i in range(900)]
    db.orders.insert_many(orders)
    db.payments.insert_many([{"order": DBRef("orders", orders[i]["_id"]), "card_number": "4111111111111111", "amount": 5.0} for i in range(400)])
    i = object.__new__(dbmongo.MongoInspector)
    i.client = i.conn = client; i.db = _Db(db); i.database = "shop"; i._version = "7.0"
    return i


def test_schema_is_inferred_with_relations(insp):
    tables, rels = insp.schema()
    by = {t.name: t for t in tables}
    assert set(by) == {"customers", "products", "orders", "payments"} and all(t.kind == "collection" for t in tables)
    cols = {c.name: c for c in by["customers"].columns}
    assert cols["_id"].pk and cols["name.first"].type == "string" and cols["tags"].type == "string[]" and cols["phone"].nullable and "in " in cols["name.last"].comment
    assert {c.name for c in by["orders"].columns} >= {"items", "items[].product_id", "items[].qty"}
    found = {(r.from_table, r.from_columns[0], r.to_table, r.inferred) for r in rels}
    assert found == {("shop.orders", "customerId", "shop.customers", True), ("shop.orders", "items[].product_id", "shop.products", True), ("shop.payments", "order", "shop.orders", False)}


def test_report_profiles_and_masks(insp):
    tables, rels = insp.schema()
    rep = dbinspect.build_report(insp, tables, rels, [{"table": "shop.customers"}, {"table": "shop.orders"}, {"table": "shop.payments"}], sample_rows=3)
    assert rep["overview"].startswith("This report covers 3 collections with 1,600 documents")
    assert any("Found by matching ids" in r["text"] for r in rep["relations"])
    sec = {s["name"]: s for s in rep["tables"]}
    cust = {c["name"]: c for c in sec["customers"]["profile"]["columns"]}
    assert cust["phone"]["null_pct"] == 33.3 and cust["name.last"]["null_pct"] == 25.0 and cust["country"]["distinct"] == 3
    assert [t["value"] for t in cust["country"]["top"]] and "top" not in cust["password_hash"] and "min" not in cust["password_hash"]
    orders = {c["name"]: c for c in sec["orders"]["profile"]["columns"]}
    assert orders["total"]["min"] == 10.0 and orders["total"]["max"] == 59.0 and orders["placed_at"]["max"].startswith("2026-11-01")
    assert all(row[[c["name"] for c in sec["payments"]["profile"]["columns"]].index("card_number")] == "•••" for row in sec["payments"]["profile"]["sample"])
    pay_cols = [c["name"] for c in sec["payments"]["profile"]["columns"]]
    assert "4111111111111111" not in str(rep) and sec["payments"]["profile"]["sample"][0][pay_cols.index("order")].startswith("orders/")
    assert "is a collection with 300 documents" in sec["customers"]["summary"]
    assert not any(q["column"] == "name" and "Unique" in q["text"] for q in sec["customers"]["quality"])           # objects are never suggested as keys


def test_quick_queries(insp):
    from app import dbquery
    tables, _ = insp.schema()
    orders = next(t for t in tables if t.name == "orders")
    r = dbquery.run(insp, orders, {"measures": [{"fn": "count"}, {"fn": "avg", "column": "total"}, {"fn": "max", "column": "total"}]})
    assert r["rows"][0][0] == 900 and r["rows"][0][2] == 59.0 and r["language"] == "mongodb" and r["query"].startswith("db.orders.aggregate(")
    g = dbquery.run(insp, orders, {"measures": [{"fn": "count"}], "group_by": [{"column": "status"}], "order": "group_asc"})
    assert g["rows"] == [["paid", 450], ["shipped", 450]]
    f = dbquery.run(insp, orders, {"measures": [{"fn": "count"}], "filters": [{"column": "total", "op": "gte", "value": "50"}, {"column": "status", "op": "eq", "value": "paid"}]})
    assert f["rows"][0][0] == 90
    customers = next(t for t in tables if t.name == "customers")
    d = dbquery.run(insp, customers, {"measures": [{"fn": "count_distinct", "column": "country"}]})
    assert d["rows"][0][0] == 3
    inj = dbquery.run(insp, customers, {"measures": [{"fn": "count"}], "filters": [{"column": "country", "op": "eq", "value": '{"$ne": null}'}]})
    assert inj["rows"] == [] or inj["rows"][0][0] == 0                       # a value is a plain value, never an operator
    with pytest.raises(dbinspect.DbError, match="sensitive"):
        dbquery.run(insp, customers, {"measures": [{"fn": "min", "column": "password_hash"}]})


def test_slow_queries_never_fail(insp):
    """Without the profiler (mongomock has none) the page still answers, and says how to turn profiling on."""
    from app import dbslow
    r = dbslow.slow_queries(insp)
    assert r["engine"] == "mongodb" and r["statements"] == [] and "setProfilingLevel" in r["note"]
    assert dbslow._shape({"email": "a@b.c", "total": {"$gt": 5}, "tags": ["x", "y"]}) == {"email": "?", "total": {"$gt": "?"}, "tags": ["?", "?"]}   # values never shown
