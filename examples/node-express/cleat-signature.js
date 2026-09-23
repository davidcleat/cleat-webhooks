// Verifying Cleat's webhook signature with node:crypto.
//
// Cleat sends:
//   cleat-signature: t=<unix seconds>,v1=<hex>
//
// v1 is HMAC-SHA256, keyed with the endpoint's signing secret (it starts with
// `whsec_`), over the ASCII string "<t>" + "." + "<raw request body>",
// hex-encoded lowercase.
//
// Two rules that matter more than the code itself:
//   1. Verify over the RAW BYTES of the request, before parsing JSON.
//   2. Compare in constant time, so a wrong signature does not leak how wrong.

import { createHmac, timingSafeEqual } from "node:crypto";

/** Cleat's own documented example uses a 300 second tolerance. */
export const DEFAULT_TOLERANCE_SECONDS = 300;

/**
 * Parse `t=...,v1=...`. Returns null for anything we do not fully understand,
 * which the caller must treat as "unsigned".
 *
 * Unknown fields are skipped rather than rejected, so that if Cleat ever adds
 * a `v2=` alongside `v1=` this keeps working.
 */
function parseSignatureHeader(header) {
  if (typeof header !== "string" || header.length === 0) return null;

  let timestamp = null;
  let signature = null;

  for (const part of header.split(",")) {
    const eq = part.indexOf("=");
    if (eq === -1) return null; // not a k=v pair: malformed
    const key = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (key === "t") {
      if (timestamp !== null) return null; // repeated field: malformed
      timestamp = value;
    } else if (key === "v1") {
      if (signature !== null) return null;
      signature = value;
    }
  }

  if (timestamp === null || signature === null) return null;
  if (!/^[0-9]{1,15}$/.test(timestamp)) return null;
  if (!/^[0-9a-fA-F]{64}$/.test(signature)) return null; // SHA-256 is 32 bytes

  // Keep the timestamp as the exact string that was sent: that string, not a
  // reformatted number, is what was signed.
  return { timestampRaw: timestamp, timestamp: Number(timestamp), signature: signature.toLowerCase() };
}

/**
 * @param {object} options
 * @param {Buffer|string} options.payload raw request body, untouched
 * @param {string|undefined} options.header value of the `cleat-signature` header
 * @param {string|undefined} options.secret endpoint signing secret (`whsec_...`)
 * @param {number} [options.toleranceSeconds]
 * @param {number} [options.nowSeconds] injectable clock, for tests
 * @returns {{ok: true, timestamp: number} | {ok: false, reason: string}}
 */
export function verifyCleatSignature({
  payload,
  header,
  secret,
  toleranceSeconds = DEFAULT_TOLERANCE_SECONDS,
  nowSeconds = Math.floor(Date.now() / 1000),
}) {
  if (typeof secret !== "string" || secret.length === 0) {
    return { ok: false, reason: "missing_secret" };
  }

  const parsed = parseSignatureHeader(header);
  if (parsed === null) return { ok: false, reason: "malformed_header" };

  // Replay guard. An attacker who captures one delivery can otherwise resend it
  // forever; the timestamp is inside the signed string, so it cannot be edited.
  const ageSeconds = nowSeconds - parsed.timestamp;
  if (ageSeconds > toleranceSeconds) return { ok: false, reason: "timestamp_too_old" };
  if (ageSeconds < -toleranceSeconds) return { ok: false, reason: "timestamp_in_future" };

  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload), "utf8");
  const expected = createHmac("sha256", secret)
    .update(`${parsed.timestampRaw}.`, "utf8")
    .update(body)
    .digest();
  const provided = Buffer.from(parsed.signature, "hex");

  if (expected.length !== provided.length) return { ok: false, reason: "signature_mismatch" };
  if (!timingSafeEqual(expected, provided)) return { ok: false, reason: "signature_mismatch" };

  return { ok: true, timestamp: parsed.timestamp };
}
