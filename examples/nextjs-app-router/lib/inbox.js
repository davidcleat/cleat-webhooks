// What this example does with a verified message, plus the idempotency store.
//
// A route handler cannot be handed its dependencies (Next.js calls the exported
// POST itself), so these live at module scope. They are IN-MEMORY AND
// PER-PROCESS: on a serverless platform every cold start begins with an empty
// store and two concurrent instances share nothing, so a real deployment must
// key on the message id in its database or in a durable key-value store.

import { SeenIds } from "./seen-ids.js";

export const seen = new SeenIds();

/** Everything this process has handled, newest last. */
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
