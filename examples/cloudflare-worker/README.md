# Cleat webhook on Cloudflare Workers

A Worker that receives Cleat's webhook, verifies the signature over the raw bytes with WebCrypto, and handles each message id once.

| File | What is in it |
| --- | --- |
| `src/index.js` | `export default { fetch }`: raw bytes, verify, parse, dispatch by `type`, answer. |
| `src/cleat-signature.js` | The verification function, WebCrypto only. This is the part to copy into your own code. |
| `src/seen-ids.js` | A bounded, in-memory "have I handled this id" store, with a note on what to use instead. |
| `src/inbox.js` | The store and what to do with a verified message. Replace this with your own work. |
| `wrangler.toml` | Worker configuration. |

No dependencies at all: the Workers runtime provides `fetch`, `Request`, `Response` and `crypto.subtle`.

## Two things specific to Workers

**WebCrypto instead of node:crypto.** `crypto.subtle.importKey` with `{ name: "HMAC", hash: "SHA-256" }`, then `crypto.subtle.sign`, then a constant-time comparison written by hand, because there is no `timingSafeEqual`. The comparison XORs every byte and checks the accumulated difference at the end, so it does not return early on the first wrong byte. (`crypto.subtle.verify` with a key imported for `["verify"]` is an equally good option and compares for you.)

**The secret comes from `env`.** Never a literal in the source, and not a `[vars]` entry in `wrangler.toml` either:

```
npx wrangler secret put CLEAT_WEBHOOK_SECRET
```

For `wrangler dev`, put it in a `.dev.vars` file, which is git-ignored:

```
CLEAT_WEBHOOK_SECRET=whsec_your_endpoint_secret
```

## Run it

```
cd examples/cloudflare-worker
echo 'CLEAT_WEBHOOK_SECRET=whsec_your_endpoint_secret' > .dev.vars
npx wrangler dev
```

`wrangler dev` serves on `http://localhost:8787`, so the endpoint is `http://localhost:8787/webhooks/cleat`. Send yourself a signed delivery, from the repository root:

```
CLEAT_WEBHOOK_SECRET=whsec_your_endpoint_secret \
  node tools/send-signed-delivery.mjs http://localhost:8787/webhooks/cleat
```

Deploy with `npx wrangler deploy`, then register `https://<worker>.<subdomain>.workers.dev/webhooks/cleat` (or your own route) as the endpoint in workspace settings and use the test delivery button. A deployed Worker is already on public HTTPS, so no tunnel is needed.

## Test it

```
npm test -w cleat-webhook-cloudflare-worker
```

The tests call the exported `fetch` directly with a plain `Request` and a fake `env`. Node 22 provides the same WebCrypto API the Workers runtime does, so this runs under `node:test` with no wrangler, no `workerd` and no network.

## Taking it to production

The in-memory seen-id store is weaker here than anywhere else: a Worker runs in many isolates around the world, created and evicted freely, so two deliveries of the same message can easily land on isolates that share nothing. Key on the message id in something durable:

- Workers KV with `expirationTtl` (write if absent, then handle),
- D1 with a unique index on the message id,
- or a Durable Object if you want a single writer with strict ordering.

Cleat wants a 2xx within 10 seconds; use `ctx.waitUntil()` or Queues for anything slower.
