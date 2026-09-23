# cleat-webhooks

Runnable examples of receiving and verifying Cleat's signed webhook, in four runtimes: Node.js with Express, a Next.js App Router route handler, a Cloudflare Worker, and FastAPI.

[Cleat](https://cleat.so) rents ID-verified US mobile numbers that receive SMS/2FA codes and transcripts of incoming calls. When a message arrives, Cleat POSTs it to the endpoints you configure. This repository shows how to accept that POST safely: check the signature over the raw bytes, refuse anything stale, and handle the same message twice without doing the work twice.

This is an examples repository, not a library. There is nothing to install from npm or PyPI: copy the verification function into your own code. It is about 60 lines in every language, and copying it means you can read every line of what is guarding your endpoint.

## Install

Clone this repository, then from its root:

```
npm install            # Express and Next.js examples (Next is a dev dependency only)
```

For the FastAPI example:

```
cd examples/python-fastapi
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
```

Node 20 or newer, Python 3.10 or newer.

## The whole thing, in one file

This is the complete receiver. It runs as written: save it as `server.js` in a directory where you have run `npm install express`, then start it with `CLEAT_WEBHOOK_SECRET=whsec_your_secret node server.js`.

```js
import express from "express";
import { createHmac, timingSafeEqual } from "node:crypto";

const secret = process.env.CLEAT_WEBHOOK_SECRET; // "whsec_..." from workspace settings
const app = express();
const handled = new Set(); // per-process; see the note on idempotency below

// express.raw, not express.json: the signature covers the exact bytes Cleat sent.
app.post("/webhooks/cleat", express.raw({ type: "application/json" }), (req, res) => {
  const header = req.get("cleat-signature") ?? "";
  const match = /^t=([0-9]+),v1=([0-9a-f]{64})$/.exec(header);
  if (!match) return res.status(401).json({ error: "no signature" });
  const [, t, v1] = match;

  if (Math.abs(Math.floor(Date.now() / 1000) - Number(t)) > 300) {
    return res.status(401).json({ error: "timestamp outside tolerance" });
  }

  const expected = createHmac("sha256", secret).update(`${t}.`).update(req.body).digest();
  const provided = Buffer.from(v1, "hex");
  if (expected.length !== provided.length || !timingSafeEqual(expected, provided)) {
    return res.status(401).json({ error: "bad signature" });
  }

  const { type, data } = JSON.parse(req.body.toString("utf8"));
  if ((type === "message.received" || type === "test") && !handled.has(data.id)) {
    handled.add(data.id);
    console.log(`${data.label ?? data.from}: ${data.code ?? data.body}`);
  }
  res.status(200).json({ ok: true }); // any 2xx, within 10 seconds
});

app.listen(3000);
```

The examples in `examples/` are this, split into readable pieces, with the edge cases handled and tests around them.

To try it without waiting for a real text, sign a delivery yourself:

```
CLEAT_WEBHOOK_SECRET=whsec_test_secret node tools/send-signed-delivery.mjs http://localhost:3000/webhooks/cleat
```

`--type test`, `--id <uuid>` (to repeat a delivery), `--skew -3600` (to watch the replay guard work) and `--tamper` are all supported.

## The examples

| Directory | What it is | Run it |
| --- | --- | --- |
| [`examples/node-express`](examples/node-express) | Express server, `node:crypto`, raw body via `express.raw` | `npm start -w cleat-webhook-node-express` |
| [`examples/nextjs-app-router`](examples/nextjs-app-router) | `app/api/cleat-webhook/route.ts` exporting `POST` | `npm run dev -w cleat-webhook-nextjs-app-router` |
| [`examples/cloudflare-worker`](examples/cloudflare-worker) | `export default { fetch }`, WebCrypto, `wrangler.toml` | `npx wrangler dev` in that directory |
| [`examples/python-fastapi`](examples/python-fastapi) | FastAPI, `hmac` + `hashlib` + `compare_digest` | `uvicorn main:app --port 8000` in that directory |

Each directory has a README with its own setup. All four behave the same way: 200 on a delivery they handled, 200 on a duplicate or an unknown event type, 401 on anything they cannot authenticate, 400 on a body that is not the shape they expect.

## Tests

```
npm test                                          # all three Node examples
cd examples/python-fastapi && python -m pytest -q  # FastAPI example
```

The Node tests use the built-in runner (`node:test`), so there is no test dependency to install; the Python tests use pytest. Nothing in them touches the network: they sign their own fixtures with the fake secret `whsec_test_secret` and call the handlers directly. Each suite checks that a correctly signed body is accepted, a tampered body is rejected with 401, a stale timestamp is rejected, a far-future timestamp is rejected, a signature made with the wrong secret is rejected, malformed headers are rejected, and a message id delivered twice is handled exactly once with a 2xx both times.

## Getting a webhook endpoint

1. Create an account at [cleat.so](https://cleat.so) and get a line. A line is $24.99/month or $249.90/year, and the workspace owner verifies their identity once, because the number is registered to a real person.
2. In workspace settings, add a webhook endpoint: a public `https://` URL. Cleat shows the signing secret once, when you create it. It starts with `whsec_`. Store it the way you store any other secret, and put it in your app's environment as `CLEAT_WEBHOOK_SECRET`.
3. Still in workspace settings, use the test delivery button. It POSTs a `{"type":"test"}` event with the same body shape as a real one, which is enough to prove your endpoint, your signature check and your deploy all work.
4. API keys live in the same place, if you also want to read messages over the REST API (`Authorization: Bearer clt_...`). Only the workspace owner can create API keys and webhook endpoints.

Cleat needs to reach your endpoint over public HTTPS, so localhost cannot receive a real delivery. To test against the real thing while developing, put a tunnel in front of your local server (`cloudflared tunnel --url http://localhost:3000`, `ngrok http 3000`, `tailscale funnel 3000`, or your own preference) and register the tunnel's https URL as the endpoint. Cleat does not follow redirects, so register the final URL.

## The signature

Every delivery carries:

```
cleat-signature: t=1758621845,v1=5f0c...64 hex characters
user-agent: Cleat-Webhooks/1.0
content-type: application/json
```

- `t` is the time Cleat signed the delivery, in whole seconds since the Unix epoch.
- `v1` is HMAC-SHA256, keyed with the endpoint's signing secret, over the ASCII string `"<t>" + "." + "<raw request body>"`, hex-encoded lowercase.

To verify:

1. Take the **raw bytes** of the body, before any JSON parsing. A parsed-and-re-serialised body is a different byte string (key order, spacing and unicode escaping are the sender's choices), so it will not verify.
2. Rebuild `"<t>.<raw body>"` using the `t` from the header exactly as it was sent, and compute the HMAC with your signing secret.
3. Compare it with `v1` in **constant time** (`crypto.timingSafeEqual`, `hmac.compare_digest`, or an XOR-accumulating loop). A plain `==` on the hex string leaks how much of a guess was right.
4. Reject a `t` more than 300 seconds from your own clock, in either direction. Without that, a captured delivery can be replayed forever. 300 seconds is the tolerance used in Cleat's documented example and in these examples.
5. Answer 401 on failure, not 500. A 5xx tells Cleat the delivery failed and should be retried; an unauthenticated request should not be retried.

Parse the header defensively. Treat a missing header, a missing field, a repeated field, a non-numeric `t` or a `v1` that is not 64 hex characters as unsigned. Skip fields you do not recognise rather than rejecting them, so an added `v2=` alongside `v1=` would not break your endpoint.

## The body

```json
{
  "type": "message.received",
  "data": {
    "id": "6f1a2b3c-4d5e-4f60-8a71-9b2c3d4e5f60",
    "line": { "id": "0f9e8d7c-6b5a-4938-8271-615f4e3d2c1b", "phone": "13055550100", "label": "work" },
    "from": "32665",
    "body": "Your Facebook code is 481920",
    "code": "481920",
    "receivedAt": "2026-09-23T10:04:05.000Z",
    "service": { "id": "facebook", "name": "Facebook", "color": "#0866FF" },
    "contact": null,
    "label": "Facebook"
  }
}
```

`type` is `message.received` for a real message, or `test` for the test delivery fired from workspace settings, which carries the same `data` shape. Read the nullable fields defensively in either case, and do not require the ones your code does not use. New types may be added, so answer 200 to a type you do not recognise instead of failing.

`data` is a Cleat message:

| Field | Type | Notes |
| --- | --- | --- |
| `id` | uuid | The idempotency key. The same id can arrive more than once. |
| `line` | object | `id` (uuid), `phone` (E.164 without the leading plus, e.g. `13055550100`), `label` (string or null) |
| `from` | string | The sender as the network reported it: a phone number, or an alphanumeric sender id |
| `body` | string | The full text. For a code read out over an automated call, the transcript of the call. |
| `code` | string or null | The code as Cleat extracted it, for display. Best effort: it can be null even when the text obviously contains a code. Read `body` when it matters. |
| `receivedAt` | string | ISO 8601 |
| `service` | object or null | The sender Cleat recognised: `id`, `name`, `color`. Conservative, because several services share one short code. |
| `contact` | object or null | A name the workspace saved: `id`, `name`, `color`. A contact always wins over `service`. |
| `label` | string or null | What to show: the contact's name, else the service's name, else null |

Nothing in the payload marks a message as having come from a call rather than a text. A call's transcript is in `body`, the calling number is in `from`.

## Delivery, retries and catching up

- Cleat POSTs as soon as it has stored the message. Answer any 2xx within 10 seconds. If your work is slower than that, queue it and answer immediately.
- Each message is posted once, but a failed attempt is retried: five attempts in all, the first straight away and the rest after 30 seconds, 2 minutes, 10 minutes and an hour. Every attempt sends the same bytes with a fresh `t` and a fresh signature, so the same `data.id` can arrive more than once. **Your handler must be idempotent on `data.id`.** The examples use a small in-memory set so they run with no setup; that set is per-process, so it is wrong for anything real. Key on the message id in your database (a unique index, treating a duplicate-key error as "already handled") or in a durable key-value store with a TTL of a day or so.
- A webhook endpoint can be down. To catch up afterwards, read the REST API: `GET /api/v1/lines/{lineId}/messages?after=<receivedAt of the last message you handled>` returns messages received strictly after that moment, oldest first, so you can walk forward and keep the last `receivedAt` as your cursor.
- After the fifth failure the delivery is given up on. Workspace settings keeps every attempt and its response, and can replay any delivery — a replay sends the same body again, as a new delivery.
- A test delivery is a synthetic message with its own fresh ids, so sending two in a row is not treated as a duplicate by a handler that keys on `data.id`. Its `service`, `contact` and `label` are `null`.
- Nothing is posted at all while a line is on hold for non-payment, or before its workspace owner has verified their identity. Those messages are stored and readable over the API as soon as the reason clears, but no webhook is ever sent for them — catch up with `?after=`.
- A workspace can have up to five endpoints. Only the workspace owner can add or remove them, and the signing secret is shown once, when the endpoint is created.
- An endpoint whose URL is a Slack incoming webhook or a Microsoft Teams workflow link is not sent this envelope at all: it gets that chat app's own message format, and no `cleat-signature`, because there is no shared secret with a chat app. Everything in this repository is about an endpoint of your own.
- The API allows 120 requests per minute per key. A 429 from Cleat carries no `Retry-After` header and no rate-limit headers, so back off on your own.

## Limits worth knowing before you build on this

- Lines are **receive-only**. They receive SMS and calls; they cannot send a text, place a call, or reach 911.
- Numbers are US mobile numbers.
- A line belongs to one identity-verified owner, who verifies once. Until that verification is done the line still runs, keeps every message and posts nothing to your endpoint, and reading messages over the API answers 403 with `code: "verify_first"`. Listing lines is not gated on it.
- An unpaid line goes to `grace`: messages are held and the API answers 402 until it is resubscribed. A released number is gone.
- Most services that refuse VoIP numbers accept a real mobile line, but nobody can promise that any particular service will accept any particular number.
- These examples use their own accounts as the example throughout: your own signup, your own cloud console, your own registrar, your own QA flow.

## Links

- [cleat.so](https://cleat.so)
- [cleat.so/for/developers](https://cleat.so/for/developers) — the REST API, the webhook reference and the MCP server

## License

MIT. See [LICENSE](LICENSE).
