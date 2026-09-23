// What this Worker does with a verified message, plus the idempotency store.
//
// THIS STORE IS IN-MEMORY AND PER-ISOLATE, which on Workers is weaker than
// per-process: your Worker runs in many isolates around the world and they are
// created and evicted freely, so two deliveries of the same message can easily
// land on two isolates that share nothing. It is here so the example runs with
// no setup. In a real Worker, key on the message id in something durable:
// Workers KV with `expirationTtl` (write-if-absent), D1 with a unique index, or
// a Durable Object if you need a strict single writer.

import { SeenIds } from "./seen-ids.js";

export const seen = new SeenIds();

/** Everything this isolate has handled, newest last. */
export const handled = [];

/**
 * @param {any} message the webhook's `data` object: a Cleat message
 * @param {{type: string}} context
 */
export function handleMessage(message, context) {
  // `code` is Cleat's extraction, for display, and it is best effort: it can be
  // null even when the text obviously contains a code. `body` is the full text,
  // and for a code read out over an automated call it is the call transcript.
  // Nothing in the payload marks a message as having come from a call.
  const code = typeof message.code === "string" ? message.code : null;

  handled.push({ id: message.id, type: context.type, code, body: message.body });

  console.log(
    `[cleat] ${context.type} ${message.id} from ${message.from}` +
      (code ? ` code=${code}` : " (no code extracted, read data.body)"),
  );
}

/** Test helper: forget everything. */
export function reset() {
  handled.length = 0;
  seen.clear();
}
