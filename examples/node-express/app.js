// A Cleat webhook receiver on Express. Express is the only dependency; the
// crypto is node:crypto.

import express from "express";
import { verifyCleatSignature } from "./cleat-signature.js";
import { SeenIds } from "./seen-ids.js";
import { handleMessage } from "./inbox.js";

export const WEBHOOK_PATH = "/webhooks/cleat";

/**
 * @param {object} [options]
 * @param {string} [options.secret] endpoint signing secret; defaults to CLEAT_WEBHOOK_SECRET
 * @param {SeenIds} [options.seen] idempotency store
 * @param {(message: object, context: {type: string}) => void} [options.onMessage]
 */
export function createApp({
  secret = process.env.CLEAT_WEBHOOK_SECRET,
  seen = new SeenIds(),
  onMessage = handleMessage,
} = {}) {
  const app = express();

  // express.raw keeps the body as the exact bytes Cleat sent. Do NOT use
  // express.json() here: the signature covers those bytes, and re-serialising a
  // parsed object almost never reproduces them (key order, spacing and unicode
  // escaping are all free choices of the sender). One mismatched byte and every
  // delivery looks forged.
  //
  // Cleat sends content-type: application/json. The `type` matcher below only
  // decides which requests get a raw Buffer; the signature check is what
  // decides whether to trust them.
  app.post(WEBHOOK_PATH, express.raw({ type: "application/json", limit: "1mb" }), (req, res) => {
    if (!secret) {
      // Misconfiguration, not a bad caller. Fail loudly rather than accepting
      // unverified traffic.
      console.error("[cleat] CLEAT_WEBHOOK_SECRET is not set; refusing to accept webhooks");
      return res.status(500).json({ error: "webhook secret is not configured" });
    }

    const rawBody = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);

    const verified = verifyCleatSignature({
      payload: rawBody,
      header: req.get("cleat-signature"),
      secret,
    });

    // 401, never 500: a bad signature is an unauthenticated request, and a 5xx
    // would make Cleat retry a delivery that can never succeed.
    if (!verified.ok) {
      console.warn(`[cleat] rejected a delivery: ${verified.reason}`);
      return res.status(401).json({ error: "invalid signature", reason: verified.reason });
    }

    let event;
    try {
      event = JSON.parse(rawBody.toString("utf8"));
    } catch {
      return res.status(400).json({ error: "body is not JSON" });
    }

    const type = event?.type;
    const data = event?.data;

    // "message.received" is a real incoming text or call transcript. "test" is
    // the test delivery you can fire from workspace settings; it has the same
    // body shape. Anything else is a type this code was written before: answer
    // 200 so Cleat does not retry it, and move on.
    if (type !== "message.received" && type !== "test") {
      return res.status(200).json({ ok: true, ignored: typeof type === "string" ? type : null });
    }

    if (!data || typeof data.id !== "string") {
      return res.status(400).json({ error: "event is missing data.id" });
    }

    // Idempotency. Claim the id first; if someone else already has it, this
    // delivery is a retry of work that is done, and 200 is the correct answer.
    //
    // One thing to expect while testing: a test delivery is a synthetic message
    // and may carry a placeholder id, so pressing the test button twice can be
    // reported as a duplicate. Restart the process to see a fresh one.
    if (!seen.addIfNew(data.id)) {
      return res.status(200).json({ ok: true, duplicate: true });
    }

    // Cleat wants any 2xx within 10 seconds. Keep this fast: if your real
    // handling is slow (a network call, an email), push the message onto a queue
    // here and answer immediately.
    onMessage(data, { type });

    return res.status(200).json({ ok: true });
  });

  app.get("/healthz", (_req, res) => res.status(200).json({ ok: true }));

  return app;
}
