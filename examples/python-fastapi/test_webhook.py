import hashlib
import hmac
import json
import time

import pytest
from fastapi.testclient import TestClient

import inbox
import main

# An obviously fake secret. Never put a real `whsec_` value in a repository.
SECRET = "whsec_test_secret"


def signature_header(raw_body: str, *, secret: str = SECRET, timestamp: int | None = None) -> str:
    """Sign a body the way Cleat does: HMAC-SHA256 over "<t>.<raw body>", hex.

    Written out longhand on purpose: the test must not borrow the function it is
    checking, or a wrong scheme on both sides would still pass.
    """
    if timestamp is None:
        timestamp = int(time.time())
    v1 = hmac.new(
        secret.encode("utf-8"), f"{timestamp}.{raw_body}".encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return f"t={timestamp},v1={v1}"


def message(**overrides):
    base = {
        "id": "6f1a2b3c-4d5e-4f60-8a71-9b2c3d4e5f60",
        "line": {"id": "0f9e8d7c-6b5a-4938-8271-615f4e3d2c1b", "phone": "13055550100", "label": "work"},
        "from": "32665",
        "body": "Your Facebook code is 481920",
        "code": "481920",
        "receivedAt": "2026-09-23T10:04:05.000Z",
        "service": {"id": "facebook", "name": "Facebook", "color": "#0866FF"},
        "contact": None,
        "label": "Facebook",
    }
    base.update(overrides)
    return base


def delivery(event_type: str = "message.received", data=None) -> str:
    return json.dumps({"type": event_type, "data": message() if data is None else data})


@pytest.fixture(autouse=True)
def fresh(monkeypatch):
    monkeypatch.setenv("CLEAT_WEBHOOK_SECRET", SECRET)
    inbox.reset()
    main.seen.clear()
    yield
    inbox.reset()
    main.seen.clear()


@pytest.fixture
def client():
    # TestClient talks to the ASGI app in-process: no socket, no network.
    with TestClient(main.app) as c:
        yield c


def post(client, raw_body: str, header: str | None):
    headers = {"content-type": "application/json", "user-agent": "Cleat-Webhooks/1.0"}
    if header is not None:
        headers["cleat-signature"] = header
    return client.post(main.WEBHOOK_PATH, content=raw_body, headers=headers)


def test_correctly_signed_delivery_is_accepted_and_handled_once(client):
    raw = delivery()
    res = post(client, raw, signature_header(raw))
    assert res.status_code == 200
    assert res.json()["ok"] is True
    assert len(inbox.handled) == 1
    assert inbox.handled[0]["code"] == "481920"


def test_test_delivery_from_workspace_settings_is_accepted(client):
    raw = delivery("test")
    res = post(client, raw, signature_header(raw))
    assert res.status_code == 200
    assert len(inbox.handled) == 1
    assert inbox.handled[0]["type"] == "test"


def test_unknown_event_type_is_ignored_with_200(client):
    raw = delivery("line.something.new")
    res = post(client, raw, signature_header(raw))
    assert res.status_code == 200
    assert res.json()["ignored"] == "line.something.new"
    assert inbox.handled == []


def test_tampered_body_is_rejected(client):
    raw = delivery()
    header = signature_header(raw)  # signature of the original bytes
    tampered = delivery(data=message(code="000000", body="Your Facebook code is 000000"))
    res = post(client, tampered, header)
    assert res.status_code == 401
    assert res.json()["reason"] == "signature_mismatch"
    assert inbox.handled == []


def test_single_flipped_byte_is_rejected(client):
    raw = delivery()
    header = signature_header(raw)
    res = post(client, raw.replace("481920", "481921"), header)
    assert res.status_code == 401


def test_stale_timestamp_is_rejected(client):
    raw = delivery()
    res = post(client, raw, signature_header(raw, timestamp=int(time.time()) - 3600))
    assert res.status_code == 401
    assert res.json()["reason"] == "timestamp_too_old"
    assert inbox.handled == []


def test_far_future_timestamp_is_rejected(client):
    raw = delivery()
    res = post(client, raw, signature_header(raw, timestamp=int(time.time()) + 3600))
    assert res.status_code == 401
    assert res.json()["reason"] == "timestamp_in_future"


def test_wrong_secret_is_rejected(client):
    raw = delivery()
    res = post(client, raw, signature_header(raw, secret="whsec_not_the_secret"))
    assert res.status_code == 401
    assert res.json()["reason"] == "signature_mismatch"
    assert inbox.handled == []


def test_malformed_or_missing_headers_are_rejected(client):
    raw = delivery()
    good = signature_header(raw)
    v1 = good.split("v1=")[1]
    now = int(time.time())
    cases = [
        None,  # no header at all
        "",
        "nonsense",
        f"v1={v1}",  # no timestamp
        f"t={now}",  # no signature
        f"t=not-a-number,v1={v1}",
        f"t={now},v1=deadbeef",  # right shape, wrong length
        f"t={now},v1={'z' * 64}",  # not hex
        f"{good},v1={v1}",  # repeated field
    ]
    for header in cases:
        inbox.reset()
        main.seen.clear()
        res = post(client, raw, header)
        assert res.status_code == 401, f"expected 401 for header {header!r}"
        assert inbox.handled == []


def test_same_message_id_twice_is_handled_once(client):
    raw = delivery()
    first = post(client, raw, signature_header(raw))
    # A retry is re-signed with a new timestamp, but the message id is the same.
    second = post(client, raw, signature_header(raw, timestamp=int(time.time()) + 5))
    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json()["duplicate"] is True
    assert len(inbox.handled) == 1


def test_valid_signature_over_non_json_is_400(client):
    raw = "this is not json"
    res = post(client, raw, signature_header(raw))
    assert res.status_code == 400


def test_no_secret_configured_accepts_nothing(client, monkeypatch):
    monkeypatch.delenv("CLEAT_WEBHOOK_SECRET", raising=False)
    raw = delivery()
    res = post(client, raw, signature_header(raw))
    assert res.status_code == 500
    assert inbox.handled == []
