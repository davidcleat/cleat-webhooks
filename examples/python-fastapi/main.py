"""A Cleat webhook receiver on FastAPI.

Run it with::

    CLEAT_WEBHOOK_SECRET=whsec_... uvicorn main:app --port 8000

The only third-party dependency is FastAPI itself; the crypto is hmac and
hashlib from the standard library.
"""

from __future__ import annotations

import json
import os
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from cleat_signature import verify_cleat_signature
from inbox import handle_message, handled
from seen_ids import SeenIds

WEBHOOK_PATH = "/webhooks/cleat"

app = FastAPI(title="Cleat webhook example")

# Idempotency store. See seen_ids.py: in-memory and per-process on purpose, and
# not what a real deployment should rely on.
seen = SeenIds()


@app.post(WEBHOOK_PATH)
async def cleat_webhook(request: Request) -> JSONResponse:
    # Read the secret per request so that rotating it (and the tests) do not need
    # a restart. Never a literal in the source.
    secret = os.environ.get("CLEAT_WEBHOOK_SECRET")
    if not secret:
        # Misconfiguration, not a bad caller. Fail loudly rather than accepting
        # unverified traffic.
        print("[cleat] CLEAT_WEBHOOK_SECRET is not set; refusing to accept webhooks")
        return JSONResponse({"error": "webhook secret is not configured"}, status_code=500)

    # The RAW bytes. The signature covers exactly what Cleat sent, so this must
    # not be a parsed body: `await request.json()` gives a dict, and
    # re-serialising it almost never reproduces those bytes (key order, spacing
    # and unicode escaping are the sender's choices, not ours). One byte out and
    # every real delivery looks forged. Do not declare a Pydantic model body
    # here either, for the same reason: parse the bytes yourself, after checking
    # them.
    raw_body = await request.body()

    verified = verify_cleat_signature(
        payload=raw_body,
        header=request.headers.get("cleat-signature"),
        secret=secret,
    )

    # 401, never 500: a bad signature is an unauthenticated request, and a 5xx
    # would make Cleat retry a delivery that can never succeed.
    if not verified.ok:
        print(f"[cleat] rejected a delivery: {verified.reason}")
        return JSONResponse({"error": "invalid signature", "reason": verified.reason}, status_code=401)

    try:
        event: Any = json.loads(raw_body)
    except ValueError:
        return JSONResponse({"error": "body is not JSON"}, status_code=400)

    if not isinstance(event, dict):
        return JSONResponse({"error": "body is not a JSON object"}, status_code=400)

    event_type = event.get("type")
    data = event.get("data")

    # "message.received" is a real incoming text or call transcript. "test" is
    # the test delivery you can fire from workspace settings; it has the same
    # body shape. Anything else is a type this code was written before: answer
    # 200 so Cleat does not retry it, and move on.
    if event_type not in ("message.received", "test"):
        ignored = event_type if isinstance(event_type, str) else None
        return JSONResponse({"ok": True, "ignored": ignored}, status_code=200)

    if not isinstance(data, dict) or not isinstance(data.get("id"), str):
        return JSONResponse({"error": "event is missing data.id"}, status_code=400)

    # Idempotency. Claim the id first; if someone else already has it, this
    # delivery is a retry of work that is done, and 200 is the correct answer.
    #
    # One thing to expect while testing: a test delivery is a synthetic message
    # and may carry a placeholder id, so pressing the test button twice can be
    # reported as a duplicate. Restart the process to see a fresh one.
    if not seen.add_if_new(data["id"]):
        return JSONResponse({"ok": True, "duplicate": True}, status_code=200)

    # Cleat wants any 2xx within 10 seconds. Keep this fast: if your real
    # handling is slow (a network call, an email), push the message onto a queue
    # here and answer immediately.
    handle_message(data, event_type=event_type)

    return JSONResponse({"ok": True, "count": len(handled)}, status_code=200)


@app.get("/healthz")
async def healthz() -> dict[str, bool]:
    return {"ok": True}
