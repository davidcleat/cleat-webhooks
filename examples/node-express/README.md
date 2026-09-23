# Cleat webhook on Node.js with Express

An Express server that receives Cleat's webhook, verifies the signature over the raw body with `node:crypto`, and handles each message id once.

| File | What is in it |
| --- | --- |
| `cleat-signature.js` | The verification function. This is the part to copy into your own code. |
| `seen-ids.js` | A bounded, in-memory "have I handled this id" store, with a note on what to use instead. |
| `inbox.js` | What to do with a verified message. Replace this with your own work. |
| `app.js` | The route: raw body, verify, parse, dispatch by `type`, answer. |
| `server.js` | Reads the environment and listens. |

Express is the only dependency.

## Run it

From the repository root:

```
npm install
CLEAT_WEBHOOK_SECRET=whsec_your_endpoint_secret npm start -w cleat-webhook-node-express
```

It listens on `http://localhost:3000/webhooks/cleat` (set `PORT` to change that). With no `CLEAT_WEBHOOK_SECRET` it starts, warns, and answers 500 to every delivery rather than trusting anything.

Send yourself a signed delivery, from the repository root, in another shell:

```
CLEAT_WEBHOOK_SECRET=whsec_your_endpoint_secret \
  node tools/send-signed-delivery.mjs http://localhost:3000/webhooks/cleat
```

Add `--tamper`, `--skew -3600` or a repeated `--id <uuid>` to watch the rejections and the idempotency check.

## Test it

```
npm test -w cleat-webhook-node-express
```

Node's built-in test runner, no test dependencies. The suite starts the app on an ephemeral loopback port for each case; nothing leaves the machine.

## Against the real Cleat

Cleat delivers to a public `https://` URL and does not follow redirects, so localhost cannot receive a real delivery. Put a tunnel in front of the local server and register the tunnel URL as your endpoint in workspace settings:

```
cloudflared tunnel --url http://localhost:3000
# then register https://<something>.trycloudflare.com/webhooks/cleat
```

`ngrok http 3000` or `tailscale funnel 3000` do the same job. Then use the test delivery button in workspace settings.

## Taking it to production

- Put the signing secret in your environment or secret manager. Never in the source.
- Replace the in-memory seen-id store with your database or a durable key-value store, keyed on the message id.
- Answer within 10 seconds. If the real work is slow, enqueue it and answer immediately.
- Keep the body parser raw on this route only. `express.json()` elsewhere in your app is fine; on this route it would break every signature.
