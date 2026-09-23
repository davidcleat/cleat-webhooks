// Verifying Cleat's webhook signature with WebCrypto.
//
// Cleat sends:
//   cleat-signature: t=<unix seconds>,v1=<hex>
//
// v1 is HMAC-SHA256, keyed with the endpoint's signing secret (it starts with
// `whsec_`), over the ASCII string "<t>" + "." + "<raw request body>",
// hex-encoded lowercase.
//
// On Workers there is no node:crypto by default, and the runtime's own
// `crypto.subtle` is the idiomatic choice. Everything below runs unchanged in
// any WebCrypto environment (Workers, Deno, Bun, browsers, modern Node).

/** Cleat's own documented example uses a 300 second tolerance. */
export const DEFAULT_TOLERANCE_SECONDS = 300;

const encoder = new TextEncoder();

/**
 * Parse `t=...,v1=...`. Returns null for anything not fully understood, which
 * the caller must treat as unsigned. Unknown fields are skipped rather than
 * rejected, so an added `v2=` would not break this.
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

/** 64 lowercase hex characters -> 32 bytes. The caller has already validated the shape. */
function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/**
 * Compare two byte arrays without an early return, so the time taken does not
 * depend on how much of the signature an attacker guessed correctly.
 */
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * @param {object} options
 * @param {Uint8Array|ArrayBuffer|string} options.payload raw request body, untouched
 * @param {string|null|undefined} options.header value of the `cleat-signature` header
 * @param {string|undefined} options.secret endpoint signing secret (`whsec_...`)
 * @param {number} [options.toleranceSeconds]
 * @param {number} [options.nowSeconds] injectable clock, for tests
 * @returns {Promise<{ok: true, timestamp: number} | {ok: false, reason: string}>}
 */
export async function verifyCleatSignature({
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

  const body =
    typeof payload === "string"
      ? encoder.encode(payload)
      : payload instanceof Uint8Array
        ? payload
        : new Uint8Array(payload);

  // The signed string is "<t>.<body>". Build those bytes without turning the
  // body into a string: the signature is over bytes, and a body that is not
  // valid UTF-8 must still verify byte for byte.
  const prefix = encoder.encode(`${parsed.timestampRaw}.`);
  const signedBytes = new Uint8Array(prefix.length + body.length);
  signedBytes.set(prefix, 0);
  signedBytes.set(body, prefix.length);

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const expected = new Uint8Array(await crypto.subtle.sign("HMAC", key, signedBytes));

  // crypto.subtle.verify (with a key imported for ["verify"]) would also work
  // and compares for you; signing and comparing here keeps the constant-time
  // step visible and is the same amount of work.
  if (!constantTimeEqual(expected, hexToBytes(parsed.signature))) {
    return { ok: false, reason: "signature_mismatch" };
  }

  return { ok: true, timestamp: parsed.timestamp };
}
