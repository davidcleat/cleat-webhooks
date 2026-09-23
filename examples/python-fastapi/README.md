# Cleat webhook on FastAPI

A FastAPI app that receives Cleat's webhook, verifies the signature over the raw body with `hmac` and `hashlib`, and handles each message id once.

| File | What is in it |
| --- | --- |
| `cleat_signature.py` | The verification function, standard library only. This is the part to copy into your own code. |
| `seen_ids.py` | A bounded, in-memory "have I handled this id" store, with a note on what to use instead. |
| `inbox.py` | What to do with a verified message. Replace this with your own work. |
| `main.py` | The route: raw body, verify, parse, dispatch by `type`, answer. |
| `test_webhook.py` | pytest suite. |

FastAPI is the only third-party runtime dependency.

## One thing specific to FastAPI

Take the raw body with `await request.body()`, and do not declare a Pydantic model for this route. A parsed-and-re-serialised body is a different byte string from the one Cleat signed, so the signature would never match. Verify the bytes, then `json.loads` those same bytes.

## Run it

```
cd examples/python-fastapi
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
CLEAT_WEBHOOK_SECRET=whsec_your_endpoint_secret uvicorn main:app --port 8000
```

The endpoint is `http://localhost:8000/webhooks/cleat`. With no `CLEAT_WEBHOOK_SECRET` set it starts and answers 500 to every delivery rather than trusting anything.

Send yourself a signed delivery, from the repository root:

```
CLEAT_WEBHOOK_SECRET=whsec_your_endpoint_secret \
  node tools/send-signed-delivery.mjs http://localhost:8000/webhooks/cleat
```

(That helper is Node, for convenience. Nothing in this example needs Node: `test_webhook.py` signs its own fixtures in Python.)

## Test it

```
python -m pytest -q
```

`TestClient` talks to the ASGI app in process, so there is no socket and no network.

## Against the real Cleat

Cleat delivers to a public `https://` URL and does not follow redirects, so localhost cannot receive a real delivery. Put a tunnel in front of the local server (`cloudflared tunnel --url http://localhost:8000`, `ngrok http 8000`) and register the tunnel URL as the endpoint in workspace settings, then use the test delivery button.

## Taking it to production

- The in-memory seen-id store is per process, and `uvicorn --workers 4` means four of them. Key on the message id in your database (a unique index, treating the duplicate-key error as "already handled") or in Redis with `SET key value NX EX 86400`.
- Answer within 10 seconds. If the real work is slow, put it on a queue and answer immediately.
- Keep the handler `async def` and do not block the event loop in it.
