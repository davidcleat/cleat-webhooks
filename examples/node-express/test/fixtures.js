// Test fixtures. The secret is a literal fake: never put a real `whsec_` value
// in a repository.
import { createHmac } from "node:crypto";

export const SECRET = "whsec_test_secret";

/**
 * Sign a body the way Cleat does: HMAC-SHA256 over "<t>.<raw body>", hex.
 *
 * Written out longhand on purpose. The tests must not borrow the function they
 * are checking, or a wrong scheme on both sides would still pass.
 */
export function signatureHeader(rawBody, { secret = SECRET, timestamp = Math.floor(Date.now() / 1000) } = {}) {
  const v1 = createHmac("sha256", secret).update(`${timestamp}.${rawBody}`, "utf8").digest("hex");
  return `t=${timestamp},v1=${v1}`;
}

/** A message shaped exactly like Cleat's webhook `data`. */
export function message(overrides = {}) {
  return {
    id: "6f1a2b3c-4d5e-4f60-8a71-9b2c3d4e5f60",
    line: { id: "0f9e8d7c-6b5a-4938-8271-615f4e3d2c1b", phone: "13055550100", label: "work" },
    from: "32665",
    body: "Your Facebook code is 481920",
    code: "481920",
    receivedAt: "2026-09-23T10:04:05.000Z",
    service: { id: "facebook", name: "Facebook", color: "#0866FF" },
    contact: null,
    label: "Facebook",
    ...overrides,
  };
}

/** The raw bytes of a delivery, as a string. */
export function delivery({ type = "message.received", data = message() } = {}) {
  return JSON.stringify({ type, data });
}
