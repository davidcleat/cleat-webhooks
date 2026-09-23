# Cleat webhook in a Next.js App Router route handler

`app/api/cleat-webhook/route.ts` exports `POST`, verifies the signature over the raw body with `node:crypto`, and handles each message id once.

| File | What is in it |
| --- | --- |
| `app/api/cleat-webhook/route.ts` | The route handler: raw body, verify, parse, dispatch by `type`, answer. |
| `lib/cleat-signature.js` | The verification function. This is the part to copy into your own code. |
| `lib/seen-ids.js` | A bounded, in-memory "have I handled this id" store, with a note on what to use instead. |
| `lib/inbox.js` | The store and what to do with a verified message. Replace this with your own work. |

The `lib` files are plain JavaScript with JSDoc types, so the same files run in the Next.js build and under `node --test` with no build step. Next.js itself is a devDependency: nothing in the handler imports it, so the tests need no Next.js server.

## Two things specific to Next.js

**Read the raw body.** `await request.text()` (or `arrayBuffer()`), never `await request.json()`. The signature covers the bytes Cleat sent, and `JSON.stringify` of a parsed object is a different byte string: key order, whitespace and unicode escaping are all choices the sender made. A body can only be read once, so read it as text, verify it, then `JSON.parse` that same string.

**Do not let it be cached or prerendered.** The handler sets `export const dynamic = "force-dynamic"`. A POST route is dynamic anyway, but saying so keeps it that way.

## Run it

From the repository root:

```
npm install
CLEAT_WEBHOOK_SECRET=whsec_your_endpoint_secret npm run dev -w cleat-webhook-nextjs-app-router
```

The endpoint is `http://localhost:3000/api/cleat-webhook`. In a real app you would put the secret in `.env.local` instead (it is git-ignored here).

Send yourself a signed delivery, from the repository root:

```
CLEAT_WEBHOOK_SECRET=whsec_your_endpoint_secret \
  node tools/send-signed-delivery.mjs http://localhost:3000/api/cleat-webhook
```

## Test it

```
npm test -w cleat-webhook-nextjs-app-router
```

The tests import the exported `POST` and call it with a plain `Request`, so there is no server, no build and no network. Node runs the TypeScript directly by stripping the types (Node 22.18 or newer).

## Against the real Cleat

Cleat delivers to a public `https://` URL and does not follow redirects, so localhost cannot receive a real delivery. Either deploy and register `https://<your app>/api/cleat-webhook`, or tunnel to your dev server (`cloudflared tunnel --url http://localhost:3000`, `ngrok http 3000`) and register the tunnel URL. Then use the test delivery button in workspace settings.

## Taking it to production

- The idempotency store here is module scope, which on a serverless platform means per instance: a cold start begins with an empty store, and two instances share nothing. Key on the message id in your database or in a durable key-value store instead.
- Answer within 10 seconds. A function that is still running has not answered yet, so hand slow work to a queue or a background job.
- Set `CLEAT_WEBHOOK_SECRET` in your hosting platform's environment variables, not in the repository.
