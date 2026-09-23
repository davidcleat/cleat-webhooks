// What this example does with a verified message.
//
// Replace this with your own work: look the code up against the signup you
// started, forward it, unblock a waiting job. Keep it fast (see the note in
// app.js about the 10 second budget) and do the slow parts on a queue.

/** Everything this process has handled, newest last. In-memory, per-process. */
export const handled = [];

/**
 * @param {object} message the webhook's `data` object: a Cleat message
 * @param {object} context
 * @param {string} context.type "message.received" or "test"
 */
export function handleMessage(message, context = {}) {
  // `code` is Cleat's extraction of the code, for display, and it is best
  // effort: it can be null even when the text clearly contains something. Read
  // `body` whenever it matters. `body` is the full text, and for a code read
  // out over an automated call it is the transcript of that call. Nothing in
  // the payload marks a message as having come from a call.
  const code = typeof message.code === "string" ? message.code : null;

  handled.push({ id: message.id, type: context.type, code, body: message.body });

  console.log(
    `[cleat] ${context.type} ${message.id} from ${message.from} on ${message.line?.phone}` +
      (code ? ` code=${code}` : " (no code extracted, read data.body)"),
  );
}

export function resetInbox() {
  handled.length = 0;
}
