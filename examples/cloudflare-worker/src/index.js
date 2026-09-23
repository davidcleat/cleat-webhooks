// A Cleat webhook receiver on Cloudflare Workers.
//
// Deploy, then point your Cleat webhook endpoint at
// https://<worker>.<subdomain>.workers.dev/webhooks/cleat.
//
// No dependencies: the runtime provides fetch, Request, Response and
// crypto.subtle.

import { verifyCleatSignature } from "./cleat-signature.js";
import { seen, handled, handleMessage } from "./inbox.js";

export const WEBHOOK_PATH = "/webhooks/cleat";

export default {
  /**
   * @param {Request} request
   * @param {{CLEAT_WEBHOOK_SECRET?: string}} env secrets come from env, never from a literal in the source
   */
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/healthz") return json({ ok: true }, 200);
    if (url.pathname !== WEBHOOK_PATH) return json({ error: "not found" }, 404);
    if (request.method !== "POST") return json({ error: "method not allowed" }, 405);

    // `npx wrangler secret put CLEAT_WEBHOOK_SECRET` for deployments, and
    // .dev.vars (git-ignored) for `wrangler dev`.
    const secret = env.CLEAT_WEBHOOK_SECRET;
    if (!secret) {
      // Misconfiguration, not a bad caller. Fail loudly rather than accepting
      // unverified traffic.
      console.error("[cleat] CLEAT_WEBHOOK_SECRET is not set; refusing to accept webhooks");
      return json({ error: "webhook secret is not configured" }, 500);
    }

    // The RAW bytes. The signature covers exactly what Cleat sent, so this must
    // not be a parsed body: `await request.json()` gives an object, and
    // re-serialising it almost never reproduces those bytes (key order, spacing
    // and unicode escaping are the sender's choices). One byte out and every
    // real delivery looks forged. A Request body can only be read once, so read
    // it here and parse the same bytes further down.
    const rawBody = new Uint8Array(await request.arrayBuffer());

    const verified = await verifyCleatSignature({
      payload: rawBody,
      header: request.headers.get("cleat-signature"),
      secret,
    });

    // 401, never 500: a bad signature is an unauthenticated request, and a 5xx
    // would make Cleat retry a delivery that can never succeed.
    if (!verified.ok) {
      console.warn(`[cleat] rejected a delivery: ${verified.reason}`);
      return json({ error: "invalid signature", reason: verified.reason }, 401);
    }

    let event;
    try {
      event = JSON.parse(new TextDecoder().decode(rawBody));
    } catch {
      return json({ error: "body is not JSON" }, 400);
    }

    const type = event?.type;
    const data = event?.data;

    // "message.received" is a real incoming text or call transcript. "test" is
    // the test delivery you can fire from workspace settings; same body shape.
    // Anything else is newer than this code: answer 200 so Cleat does not retry.
    if (type !== "message.received" && type !== "test") {
      return json({ ok: true, ignored: typeof type === "string" ? type : null }, 200);
    }

    if (!data || typeof data.id !== "string") {
      return json({ error: "event is missing data.id" }, 400);
    }

    // Idempotency. Cleat retries a failed delivery on a backoff, so the same
    // data.id can arrive twice. Claim the id first; if it was already claimed
    // the work is done and 200 is the right answer.
    //
    // One thing to expect while testing: a test delivery is a synthetic message
    // and may carry a placeholder id, so pressing the test button twice can be
    // reported as a duplicate. Restart the process (or clear the store) to see
    // a fresh one.
    if (!seen.addIfNew(data.id)) {
      return json({ ok: true, duplicate: true }, 200);
    }

    // Cleat wants any 2xx within 10 seconds. Keep this fast: for slow work, use
    // ctx.waitUntil() or a queue and answer now.
    handleMessage(data, { type });

    return json({ ok: true, count: handled.length }, 200);
  },
};

function json(body, status) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}
