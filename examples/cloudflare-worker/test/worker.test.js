import test from "node:test";
import assert from "node:assert/strict";
import worker, { WEBHOOK_PATH } from "../src/index.js";
import { handled, reset } from "../src/inbox.js";

// An obviously fake secret. Never put a real `whsec_` value in a repository.
const SECRET = "whsec_test_secret";
const env = { CLEAT_WEBHOOK_SECRET: SECRET };

// The Worker's exported fetch() is called directly with a plain Request and a
// fake env: no wrangler, no server, no network. Node 22 provides the same
// WebCrypto the Workers runtime does, so the signing below and the verification
// inside the Worker use the same primitives it will use in production.

const encoder = new TextEncoder();

/**
 * Sign a body the way Cleat does: HMAC-SHA256 over "<t>.<raw body>", hex.
 * Written out longhand so the test does not borrow the code it is checking.
 */
async function signatureHeader(rawBody, { secret = SECRET, timestamp = Math.floor(Date.now() / 1000) } = {}) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = await crypto.subtle.sign("HMAC", key, encoder.encode(`${timestamp}.${rawBody}`));
  const v1 = [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return `t=${timestamp},v1=${v1}`;
}

function message(overrides = {}) {
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

function delivery({ type = "message.received", data = message() } = {}) {
  return JSON.stringify({ type, data });
}

async function post(rawBody, header, workerEnv = env) {
  const headers = { "content-type": "application/json", "user-agent": "Cleat-Webhooks/1.0" };
  if (header !== undefined) headers["cleat-signature"] = header;
  const request = new Request(`https://worker.example.com${WEBHOOK_PATH}`, { method: "POST", headers, body: rawBody });
  const res = await worker.fetch(request, workerEnv);
  return { status: res.status, body: await res.json() };
}

test.beforeEach(() => reset());

test("a correctly signed delivery is accepted and handled once", async () => {
  const raw = delivery();
  const res = await post(raw, await signatureHeader(raw));
  assert.equal(res.status, 200);
  assert.equal(res.body.ok, true);
  assert.equal(handled.length, 1);
  assert.equal(handled[0].code, "481920");
});

test("a test delivery from workspace settings is accepted", async () => {
  const raw = delivery({ type: "test" });
  const res = await post(raw, await signatureHeader(raw));
  assert.equal(res.status, 200);
  assert.equal(handled.length, 1);
  assert.equal(handled[0].type, "test");
});

test("an unknown event type is ignored with a 200", async () => {
  const raw = delivery({ type: "line.something.new" });
  const res = await post(raw, await signatureHeader(raw));
  assert.equal(res.status, 200);
  assert.equal(res.body.ignored, "line.something.new");
  assert.equal(handled.length, 0);
});

test("a tampered body is rejected with 401", async () => {
  const raw = delivery();
  const header = await signatureHeader(raw); // signature of the original bytes
  const tampered = delivery({ data: message({ code: "000000", body: "Your Facebook code is 000000" }) });
  const res = await post(tampered, header);
  assert.equal(res.status, 401);
  assert.equal(res.body.reason, "signature_mismatch");
  assert.equal(handled.length, 0);
});

test("a stale timestamp is rejected with 401", async () => {
  const raw = delivery();
  const res = await post(raw, await signatureHeader(raw, { timestamp: Math.floor(Date.now() / 1000) - 3600 }));
  assert.equal(res.status, 401);
  assert.equal(res.body.reason, "timestamp_too_old");
  assert.equal(handled.length, 0);
});

test("a far-future timestamp is rejected with 401", async () => {
  const raw = delivery();
  const res = await post(raw, await signatureHeader(raw, { timestamp: Math.floor(Date.now() / 1000) + 3600 }));
  assert.equal(res.status, 401);
  assert.equal(res.body.reason, "timestamp_in_future");
});

test("a signature made with the wrong secret is rejected with 401", async () => {
  const raw = delivery();
  const res = await post(raw, await signatureHeader(raw, { secret: "whsec_not_the_secret" }));
  assert.equal(res.status, 401);
  assert.equal(res.body.reason, "signature_mismatch");
  assert.equal(handled.length, 0);
});

test("malformed or missing signature headers are rejected with 401", async () => {
  const raw = delivery();
  const good = await signatureHeader(raw);
  const v1 = good.split("v1=")[1];
  const now = Math.floor(Date.now() / 1000);
  const cases = [undefined, "", "nonsense", `v1=${v1}`, `t=${now}`, `t=not-a-number,v1=${v1}`, `t=${now},v1=deadbeef`, `t=${now},v1=${"z".repeat(64)}`, `${good},v1=${v1}`];
  for (const header of cases) {
    reset();
    const res = await post(raw, header);
    assert.equal(res.status, 401, `expected 401 for header ${JSON.stringify(header)}`);
    assert.equal(handled.length, 0);
  }
});

test("the same message id delivered twice is handled once, both times 2xx", async () => {
  const raw = delivery();
  const first = await post(raw, await signatureHeader(raw));
  // A retry is re-signed with a new timestamp, but the message id is the same.
  const second = await post(raw, await signatureHeader(raw, { timestamp: Math.floor(Date.now() / 1000) + 5 }));
  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  assert.equal(second.body.duplicate, true);
  assert.equal(handled.length, 1);
});

test("a valid signature over a body that is not JSON is a 400", async () => {
  const raw = "this is not json";
  const res = await post(raw, await signatureHeader(raw));
  assert.equal(res.status, 400);
});

test("with no secret in env nothing is accepted", async () => {
  const raw = delivery();
  const res = await post(raw, await signatureHeader(raw), {});
  assert.equal(res.status, 500);
  assert.equal(handled.length, 0);
});

test("a GET on the webhook path is a 405 and another path is a 404", async () => {
  const get = await worker.fetch(new Request(`https://worker.example.com${WEBHOOK_PATH}`), env);
  assert.equal(get.status, 405);
  const other = await worker.fetch(new Request("https://worker.example.com/somewhere-else", { method: "POST" }), env);
  assert.equal(other.status, 404);
});
