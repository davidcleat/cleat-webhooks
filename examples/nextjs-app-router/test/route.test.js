import test from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { POST } from "../app/api/cleat-webhook/route.ts";
import { handled, reset } from "../lib/inbox.js";

// An obviously fake secret. Never put a real `whsec_` value in a repository.
const SECRET = "whsec_test_secret";

/**
 * Sign a body the way Cleat does: HMAC-SHA256 over "<t>.<raw body>", hex.
 * Written out longhand so the test does not borrow the code it is checking.
 */
function signatureHeader(rawBody, { secret = SECRET, timestamp = Math.floor(Date.now() / 1000) } = {}) {
  const v1 = createHmac("sha256", secret).update(`${timestamp}.${rawBody}`, "utf8").digest("hex");
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

/** Call the route handler with a plain Request. No Next.js server involved. */
function post(rawBody, header) {
  const headers = { "content-type": "application/json", "user-agent": "Cleat-Webhooks/1.0" };
  if (header !== undefined) headers["cleat-signature"] = header;
  return POST(new Request("https://example.com/api/cleat-webhook", { method: "POST", headers, body: rawBody }));
}

async function read(res) {
  return { status: res.status, body: await res.json() };
}

test.beforeEach(() => {
  process.env.CLEAT_WEBHOOK_SECRET = SECRET;
  reset();
});

test("a correctly signed delivery is accepted and handled once", async () => {
  const raw = delivery();
  const res = await read(await post(raw, signatureHeader(raw)));
  assert.equal(res.status, 200);
  assert.equal(res.body.ok, true);
  assert.equal(handled.length, 1);
  assert.equal(handled[0].code, "481920");
});

test("a test delivery from workspace settings is accepted", async () => {
  const raw = delivery({ type: "test" });
  const res = await read(await post(raw, signatureHeader(raw)));
  assert.equal(res.status, 200);
  assert.equal(handled.length, 1);
  assert.equal(handled[0].type, "test");
});

test("an unknown event type is ignored with a 200", async () => {
  const raw = delivery({ type: "line.something.new" });
  const res = await read(await post(raw, signatureHeader(raw)));
  assert.equal(res.status, 200);
  assert.equal(res.body.ignored, "line.something.new");
  assert.equal(handled.length, 0);
});

test("a tampered body is rejected with 401", async () => {
  const raw = delivery();
  const header = signatureHeader(raw); // signature of the original bytes
  const tampered = delivery({ data: message({ code: "000000", body: "Your Facebook code is 000000" }) });
  const res = await read(await post(tampered, header));
  assert.equal(res.status, 401);
  assert.equal(res.body.reason, "signature_mismatch");
  assert.equal(handled.length, 0);
});

test("a stale timestamp is rejected with 401", async () => {
  const raw = delivery();
  const stale = Math.floor(Date.now() / 1000) - 3600;
  const res = await read(await post(raw, signatureHeader(raw, { timestamp: stale })));
  assert.equal(res.status, 401);
  assert.equal(res.body.reason, "timestamp_too_old");
  assert.equal(handled.length, 0);
});

test("a far-future timestamp is rejected with 401", async () => {
  const raw = delivery();
  const future = Math.floor(Date.now() / 1000) + 3600;
  const res = await read(await post(raw, signatureHeader(raw, { timestamp: future })));
  assert.equal(res.status, 401);
  assert.equal(res.body.reason, "timestamp_in_future");
});

test("a signature made with the wrong secret is rejected with 401", async () => {
  const raw = delivery();
  const res = await read(await post(raw, signatureHeader(raw, { secret: "whsec_not_the_secret" })));
  assert.equal(res.status, 401);
  assert.equal(res.body.reason, "signature_mismatch");
  assert.equal(handled.length, 0);
});

test("malformed or missing signature headers are rejected with 401", async () => {
  const raw = delivery();
  const good = signatureHeader(raw);
  const v1 = good.split("v1=")[1];
  const now = Math.floor(Date.now() / 1000);
  const cases = [undefined, "", "nonsense", `v1=${v1}`, `t=${now}`, `t=not-a-number,v1=${v1}`, `t=${now},v1=deadbeef`, `t=${now},v1=${"z".repeat(64)}`, `${good},v1=${v1}`];
  for (const header of cases) {
    reset();
    const res = await read(await post(raw, header));
    assert.equal(res.status, 401, `expected 401 for header ${JSON.stringify(header)}`);
    assert.equal(handled.length, 0);
  }
});

test("the same message id delivered twice is handled once, both times 2xx", async () => {
  const raw = delivery();
  const first = await read(await post(raw, signatureHeader(raw)));
  // A retry is re-signed with a new timestamp, but the message id is the same.
  const second = await read(await post(raw, signatureHeader(raw, { timestamp: Math.floor(Date.now() / 1000) + 5 })));
  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  assert.equal(second.body.duplicate, true);
  assert.equal(handled.length, 1);
});

test("a valid signature over a body that is not JSON is a 400", async () => {
  const raw = "this is not json";
  const res = await read(await post(raw, signatureHeader(raw)));
  assert.equal(res.status, 400);
});

test("with no secret configured nothing is accepted", async () => {
  delete process.env.CLEAT_WEBHOOK_SECRET;
  const raw = delivery();
  const res = await read(await post(raw, signatureHeader(raw)));
  assert.equal(res.status, 500);
  assert.equal(handled.length, 0);
});
