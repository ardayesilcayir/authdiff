import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.tokens import make_token, token_lines


@pytest.fixture()
def client():
    with TestClient(create_app()) as c:
        yield c


def h(user_id: int, name: str):
    return {"Authorization": f"Bearer {make_token(user_id, name)}"}


ADMIN = lambda: h(1, "admin")  # noqa: E731
ALICE = lambda: h(2, "alice")  # noqa: E731
BOB = lambda: h(3, "bob")  # noqa: E731


# ---- tokens -------------------------------------------------------------


def test_tokens_deterministic():
    assert make_token(2, "alice") == make_token(2, "alice")
    lines = token_lines()
    assert [ln.split("=")[0] for ln in lines] == ["ADMIN_TOKEN", "ALICE_TOKEN", "BOB_TOKEN"]


def test_unknown_user_token_is_401(client):
    r = client.get("/me", headers=h(999, "ghost"))
    assert r.status_code == 401


def test_no_token_rejected_on_protected(client):
    assert client.get("/me").status_code in (401, 403)
    assert client.get("/orders/101").status_code in (401, 403)


# ---- negatives (correct protection) ------------------------------------


def test_me(client):
    r = client.get("/me", headers=ALICE())
    assert r.status_code == 200 and r.json()["id"] == 2


def test_me_orders(client):
    r = client.get("/me/orders", headers=ALICE())
    assert [o["id"] for o in r.json()["items"]] == [101, 102]


def test_users_me_get(client):
    r = client.get("/users/me", headers=BOB())
    assert r.status_code == 200 and r.json()["id"] == 3


def test_status_foreign_404(client):
    assert client.get("/orders/101/status", headers=BOB()).status_code == 404
    assert client.get("/orders/101/status", headers=ALICE()).status_code == 200


def test_products_public(client):
    assert client.get("/products").status_code == 200
    assert client.get("/products/1").status_code == 200


def test_admin_stats_requires_admin(client):
    assert client.get("/admin/stats", headers=ALICE()).status_code == 403
    assert client.get("/admin/stats", headers=ADMIN()).status_code == 200


def test_post_orders_ignores_owner_id(client):
    r = client.post(
        "/orders", headers=ALICE(), json={"item": "x", "total": 1.5, "ownerId": 3}
    )
    assert r.status_code in (200, 201)
    assert r.json()["ownerId"] == 2


# ---- vulnerabilities ----------------------------------------------------


def test_v1_bob_reads_alice_order(client):
    r = client.get("/orders/101", headers=BOB())
    assert r.status_code == 200
    assert r.json()["ownerId"] == 2


def test_v1_request_id_changes(client):
    a = client.get("/orders/101", headers=ALICE()).json()
    b = client.get("/orders/101", headers=ALICE()).json()
    assert a["requestId"] != b["requestId"]
    a.pop("requestId"), b.pop("requestId")
    assert a == b


def test_v2_bob_patches_alice_order(client):
    r = client.patch("/orders/101", headers=BOB(), json={"note": "pwned"})
    assert r.status_code == 200
    assert client.get("/orders/101", headers=ALICE()).json()["note"] == "pwned"


def test_v3_bob_reads_alice_invoice_pdf(client):
    r = client.get("/invoices/9001/pdf", headers=BOB())
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.content.startswith(b"%PDF")
    assert b"alice@vuln.lab" in r.content
    assert client.get("/invoices/9001/pdf", headers=BOB()).content == r.content


def test_v4_user_lists_admin_users(client):
    r = client.get("/admin/users", headers=ALICE())
    assert r.status_code == 200 and len(r.json()["items"]) == 3


def test_v5_user_deletes_user(client):
    assert client.delete("/admin/users/3", headers=ALICE()).status_code in (200, 204)
    assert client.get("/admin/users", headers=ADMIN()).json()["items"][-1]["id"] != 3


def test_v6_profile_no_auth(client):
    r = client.get("/users/2/profile")
    assert r.status_code == 200
    assert r.json() == {"userId": 2, "displayName": "alice", "email": "alice@vuln.lab"}


def test_v7_role_escalation(client):
    r = client.put("/users/me", headers=BOB(), json={"displayName": "b", "role": "admin"})
    assert r.status_code == 200
    me = client.get("/users/me", headers=BOB()).json()
    assert me["role"] == "admin" and me["displayName"] == "b"


def test_v8_user_leaks_password_hash(client):
    r = client.get("/users/2", headers=ALICE())
    assert r.status_code == 200 and "passwordHash" in r.json()
    assert client.get("/users/3", headers=ALICE()).status_code in (403, 404)
    assert client.get("/users/3", headers=ADMIN()).status_code == 200


# ---- openapi shape ------------------------------------------------------


def test_openapi_security_marks(client):
    spec = client.get("/openapi.json").json()
    paths = spec["paths"]
    assert "security" not in paths["/users/{userId}/profile"]["get"]
    assert "security" not in paths["/products"]["get"]
    assert paths["/orders/{orderId}"]["get"]["security"]
    assert paths["/admin/users"]["get"]["security"]
    p = paths["/orders/{orderId}"]["get"]["parameters"][0]
    assert p["schema"]["type"] == "integer"


# ---- VULNERABILITIES.md is consistent with the spec ---------------------


def test_vulnerabilities_md_paths_exist(client):
    text = (Path(__file__).parent.parent / "VULNERABILITIES.md").read_text(encoding="utf-8")
    front = text.split("---")[1]
    spec = client.get("/openapi.json").json()["paths"]
    pairs = re.findall(r"method:\s*(\w+)\s*\n\s*path:\s*(\S+)", front)
    assert len(pairs) == 16
    for method, path in pairs:
        assert method.lower() in spec[path], (method, path)
