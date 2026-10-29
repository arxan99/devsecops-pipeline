import pytest

from app.main import SECURITY_HEADERS, create_app, hash_key, load_api_keys

ALICE, BOB = "alice-test-key-123", "bob-test-key-456"


@pytest.fixture
def client(tmp_path):
    app = create_app({
        "DB_PATH": str(tmp_path / "notes.db"),
        "API_KEY_HASHES": f"alice:{hash_key(ALICE)},bob:{hash_key(BOB)}",
        "RATE_LIMIT_PER_MIN": 5,
    })
    return app.test_client()


def auth(key):
    return {"X-API-Key": key}


def test_health_and_ready(client):
    assert client.get("/healthz").status_code == 200
    assert client.get("/readyz").status_code == 200


def test_not_ready_without_keys(tmp_path):
    c = create_app({"DB_PATH": str(tmp_path / "x.db"), "API_KEY_HASHES": ""}).test_client()
    assert c.get("/readyz").status_code == 503


def test_security_headers_on_every_response(client):
    for resp in (client.get("/healthz"), client.get("/api/v1/notes"), client.get("/nope")):
        for header, value in SECURITY_HEADERS.items():
            assert resp.headers[header] == value
        assert resp.headers["X-Request-ID"]


@pytest.mark.parametrize("headers", [{}, auth("wrong-key"), {"X-API-Key": ""}])
def test_rejects_bad_api_keys(client, headers):
    resp = client.get("/api/v1/notes", headers=headers)
    assert resp.status_code == 401
    assert "request_id" in resp.get_json()


def test_crud(client):
    resp = client.post("/api/v1/notes", json={"title": " Hello ", "body": "first note"}, headers=auth(ALICE))
    assert resp.status_code == 201
    note = resp.get_json()
    assert note["title"] == "Hello"  # whitespace stripped

    assert client.get(f"/api/v1/notes/{note['id']}", headers=auth(ALICE)).get_json()["body"] == "first note"
    assert len(client.get("/api/v1/notes", headers=auth(ALICE)).get_json()) == 1
    assert client.delete(f"/api/v1/notes/{note['id']}", headers=auth(ALICE)).status_code == 204
    assert client.get(f"/api/v1/notes/{note['id']}", headers=auth(ALICE)).status_code == 404


def test_tenant_isolation(client):
    note = client.post("/api/v1/notes", json={"title": "secret", "body": "alice only"}, headers=auth(ALICE)).get_json()
    assert client.get(f"/api/v1/notes/{note['id']}", headers=auth(BOB)).status_code == 404
    assert client.delete(f"/api/v1/notes/{note['id']}", headers=auth(BOB)).status_code == 404
    assert client.get("/api/v1/notes", headers=auth(BOB)).get_json() == []


@pytest.mark.parametrize("body,status", [
    ({"title": "", "body": "x"}, 422),
    ({"title": "x" * 121, "body": "x"}, 422),
    ({"title": "ok", "body": "x", "is_admin": True}, 422),   # mass-assignment attempt
    ({"title": "ok"}, 422),
    (["not", "an", "object"], 400),
])
def test_input_validation(client, body, status):
    assert client.post("/api/v1/notes", json=body, headers=auth(ALICE)).status_code == status


def test_sql_injection_payload_is_stored_as_text(client):
    payload = "x'); DROP TABLE notes; --"
    resp = client.post("/api/v1/notes", json={"title": payload, "body": "b"}, headers=auth(ALICE))
    assert resp.status_code == 201
    assert client.get("/api/v1/notes", headers=auth(ALICE)).get_json()[0]["title"] == payload


def test_body_size_limit(client):
    big = {"title": "t", "body": "x" * 20000}
    assert client.post("/api/v1/notes", json=big, headers=auth(ALICE)).status_code == 413


def test_rate_limit(client):
    codes = [client.get("/api/v1/notes", headers=auth(ALICE)).status_code for _ in range(6)]
    assert codes[:5] == [200] * 5 and codes[5] == 429
    # other tenants are unaffected
    assert client.get("/api/v1/notes", headers=auth(BOB)).status_code == 200


def test_metrics(client):
    client.get("/api/v1/notes")
    text = client.get("/metrics").get_data(as_text=True)
    assert "notes_auth_failures_total 1" in text


def test_load_api_keys_ignores_malformed_entries():
    keys = load_api_keys(f"alice:{hash_key('k')}, bad, bob:short, :{hash_key('x')}")
    assert list(keys.values()) == ["alice"]
