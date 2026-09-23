// Verifying Cleat's webhook signature. Plain JavaScript with JSDoc types so the
// same file works in the Next.js build and under `node --test` unchanged.
//
// Cleat sends:
//   cleat-signature: t=<unix seconds>,v1=<hex>
//
// v1 is HMAC-SHA256, keyed with the endpoint's signing secret (it starts with
// `whsec_`), over the ASCII string "<t>" + "." + "<raw request body>",
// hex-encoded lowercase.

import { createHmac, timingSafeEqual } from "node:crypto";

/** Cleat's own documented example uses a 300 second tolerance. */
export const DEFAULT_TOLERANCE_SECONDS = 300;

/**
 * Parse `t=...,v1=...`. Returns null for anything not fully understood, which
 * the caller must treat as unsigned. Unknown fields are skipped rather than
 * rejected, so an added `v2=` would not break this.
 *
 * @param {string | null | undefined} header
 */
function parseSignatureHeader(header) {
  if (typeof header !== "string" || header.length === 0) return null;

  let timestamp = null;
  let signature = null;

  for (const part of header.split(",")) {
    const eq = part.indexOf("=");
    if (eq === -1) return null;
    const key = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (key === "t") {
      if (timestamp !== null) return null;
      timestamp = value;
    } else if (key === "v1") {
      if (signature !== null) return null;
      signature = value;
    }
  }

  if (timestamp === null || signature === null) return null;
  if (!/^[0-9]{1,15}$/.test(timestamp)) return null;
  if (!/^[0-9a-fA-F]{64}$/.test(signature)) return null;

  return { timestampRaw: timestamp, timestamp: Number(timestamp), signature: signature.toLowerCase() };
}

/**
 * @param {object} options
 * @param {Buffer | Uint8Array | string} options.payload raw request body, untouched
 * @param {string | null | undefined} options.header value of the `cleat-signature` header
 * @param {string | undefined} options.secret endpoint signing secret (`whsec_...`)
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

  // Replay guard: the timestamp is inside the signed string, so a captured
  // delivery cannot be re-dated, only replayed inside this window.
  const ageSeconds = nowSeconds - parsed.timestamp;
  if (ageSeconds > toleranceSeconds) return { ok: false, reason: "timestamp_too_old" };
  if (ageSeconds < -toleranceSeconds) return { ok: false, reason: "timestamp_in_future" };

  const body = typeof payload === "string" ? Buffer.from(payload, "utf8") : Buffer.from(payload);
  const expected = createHmac("sha256", secret)
    .update(`${parsed.timestampRaw}.`, "utf8")
    .update(body)
    .digest();
  const provided = Buffer.from(parsed.signature, "hex");

  if (expected.length !== provided.length) return { ok: false, reason: "signature_mismatch" };
  if (!timingSafeEqual(expected, provided)) return { ok: false, reason: "signature_mismatch" };

  return { ok: true, timestamp: parsed.timestamp };
}
