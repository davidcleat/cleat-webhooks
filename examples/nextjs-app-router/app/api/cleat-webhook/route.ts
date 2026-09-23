// A Cleat webhook receiver as a Next.js App Router route handler.
//
// Point your Cleat webhook endpoint at https://<your host>/api/cleat-webhook.
//
// Next.js is a devDependency of this example: nothing here imports it. The
// handler takes a web-standard Request and returns a web-standard Response, so
// the tests call POST() directly without starting a server.

import { verifyCleatSignature } from "../../../lib/cleat-signature.js";
import { seen, handled, handleMessage } from "../../../lib/inbox.js";

// This handler must never be prerendered or cached: it exists to be POSTed to.
export const dynamic = "force-dynamic";

export async function POST(request: Request): Promise<Response> {
  const secret = process.env.CLEAT_WEBHOOK_SECRET;
  if (!secret) {
    // Misconfiguration, not a bad caller. Fail loudly rather than accepting
    // unverified traffic.
    console.error("[cleat] CLEAT_WEBHOOK_SECRET is not set; refusing to accept webhooks");
    return json({ error: "webhook secret is not configured" }, 500);
  }

  // The RAW body, as text. The signature covers the exact bytes Cleat sent, so
  // this must not be a parsed body: `await request.json()` gives an object, and
  // re-serialising it almost never reproduces those bytes (key order, spacing
  // and unicode escaping are the sender's choices, not ours). One byte out and
  // every real delivery looks forged. Read the body once, verify it, then parse
  // the same string. `await request.arrayBuffer()` works too if you prefer
  // bytes; either way, a Request body can only be read once.
  const rawBody = await request.text();

  const verified = verifyCleatSignature({
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

  let event: { type?: unknown; data?: any };
  try {
    event = JSON.parse(rawBody);
  } catch {
    return json({ error: "body is not JSON" }, 400);
  }

  const type = event?.type;
  const data = event?.data;

  // "message.received" is a real incoming text or call transcript. "test" is the
  // test delivery you can fire from workspace settings; same body shape.
  // Anything else is newer than this code: answer 200 so Cleat does not retry.
  if (type !== "message.received" && type !== "test") {
    return json({ ok: true, ignored: typeof type === "string" ? type : null }, 200);
  }

  if (!data || typeof data.id !== "string") {
    return json({ error: "event is missing data.id" }, 400);
  }

  // Idempotency. Cleat retries a failed delivery on a backoff, so the same
  // data.id can arrive twice. Claim the id first; if it was already claimed the
  // work is done and 200 is the right answer.
  //
  // One thing to expect while testing: a test delivery is a synthetic message
  // and may carry a placeholder id, so pressing the test button twice can be
  // reported as a duplicate. Restart the dev server to see a fresh one.
  if (!seen.addIfNew(data.id)) {
    return json({ ok: true, duplicate: true }, 200);
  }

  // Cleat wants any 2xx within 10 seconds, and a serverless function that is
  // still running has not answered. Keep this fast: hand slow work to a queue.
  handleMessage(data, { type });

  return json({ ok: true, count: handled.length }, 200);
}

function json(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}
