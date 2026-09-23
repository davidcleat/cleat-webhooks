import test from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { createApp, WEBHOOK_PATH } from "../app.js";
import { SeenIds } from "../seen-ids.js";
import { SECRET, signatureHeader, message, delivery } from "./fixtures.js";

/**
 * Start the app on an ephemeral loopback port, post once, shut down. No network
 * beyond 127.0.0.1 and no test dependencies.
 */
async function post(app, rawBody, header) {
  const server = app.listen(0);
  await once(server, "listening");
  const { port } = server.address();
  try {
    const headers = { "content-type": "application/json", "user-agent": "Cleat-Webhooks/1.0" };
    if (header !== undefined) headers["cleat-signature"] = header;
    const res = await fetch(`http://127.0.0.1:${port}${WEBHOOK_PATH}`, { method: "POST", headers, body: rawBody });
    return { status: res.status, body: await res.json() };
  } finally {
    server.close();
    await once(server, "close");
  }
}

/** A fresh app with its own idempotency store and a handler we can count. */
function harness() {
  const handled = [];
  const app = createApp({
    secret: SECRET,
    seen: new SeenIds(),
    onMessage: (msg, context) => handled.push({ id: msg.id, type: context.type }),
  });
  return { app, handled };
}

test("a correctly signed delivery is accepted and handled once", async () => {
  const { app, handled } = harness();
  const raw = delivery();
  const res = await post(app, raw, signatureHeader(raw));
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { ok: true });
  assert.equal(handled.length, 1);
  assert.equal(handled[0].type, "message.received");
});

test("a test delivery from workspace settings is accepted", async () => {
  const { app, handled } = harness();
  const raw = delivery({ type: "test" });
  const res = await post(app, raw, signatureHeader(raw));
  assert.equal(res.status, 200);
  assert.equal(handled.length, 1);
  assert.equal(handled[0].type, "test");
});

test("an unknown event type is ignored with a 200", async () => {
  const { app, handled } = harness();
  const raw = delivery({ type: "line.something.new" });
  const res = await post(app, raw, signatureHeader(raw));
  assert.equal(res.status, 200);
  assert.equal(res.body.ignored, "line.something.new");
  assert.equal(handled.length, 0);
});

test("a tampered body is rejected with 401", async () => {
  const { app, handled } = harness();
  const raw = delivery();
  const header = signatureHeader(raw); // signature of the original bytes
  const tampered = delivery({ data: message({ code: "000000", body: "Your Facebook code is 000000" }) });
  const res = await post(app, tampered, header);
  assert.equal(res.status, 401);
  assert.equal(res.body.reason, "signature_mismatch");
  assert.equal(handled.length, 0);
});

test("a single flipped byte is rejected with 401", async () => {
  const { app } = harness();
  const raw = delivery();
  const header = signatureHeader(raw);
  const res = await post(app, raw.replace("481920", "481921"), header);
  assert.equal(res.status, 401);
});

test("a stale timestamp is rejected with 401", async () => {
  const { app, handled } = harness();
  const raw = delivery();
  const stale = Math.floor(Date.now() / 1000) - 3600;
  const res = await post(app, raw, signatureHeader(raw, { timestamp: stale }));
  assert.equal(res.status, 401);
  assert.equal(res.body.reason, "timestamp_too_old");
  assert.equal(handled.length, 0);
});

test("a far-future timestamp is rejected with 401", async () => {
  const { app } = harness();
  const raw = delivery();
  const future = Math.floor(Date.now() / 1000) + 3600;
  const res = await post(app, raw, signatureHeader(raw, { timestamp: future }));
  assert.equal(res.status, 401);
  assert.equal(res.body.reason, "timestamp_in_future");
});

test("a signature made with the wrong secret is rejected with 401", async () => {
  const { app, handled } = harness();
  const raw = delivery();
  const res = await post(app, raw, signatureHeader(raw, { secret: "whsec_not_the_secret" }));
  assert.equal(res.status, 401);
  assert.equal(res.body.reason, "signature_mismatch");
  assert.equal(handled.length, 0);
});

test("malformed or missing signature headers are rejected with 401", async () => {
  const raw = delivery();
  const good = signatureHeader(raw);
  const v1 = good.split("v1=")[1];
  const cases = [
    undefined, // no header at all
    "",
    "nonsense",
    `v1=${v1}`, // no timestamp
    `t=${Math.floor(Date.now() / 1000)}`, // no signature
    `t=not-a-number,v1=${v1}`,
    `t=${Math.floor(Date.now() / 1000)},v1=deadbeef`, // right shape, wrong length
    `t=${Math.floor(Date.now() / 1000)},v1=${"z".repeat(64)}`, // not hex
    `${good},v1=${v1}`, // repeated field
  ];
  for (const header of cases) {
    const { app, handled } = harness();
    const res = await post(app, raw, header);
    assert.equal(res.status, 401, `expected 401 for header ${JSON.stringify(header)}`);
    assert.equal(handled.length, 0);
  }
});

test("the same message id delivered twice is handled once, both times 2xx", async () => {
  const { app, handled } = harness();
  const raw = delivery();
  const first = await post(app, raw, signatureHeader(raw));
  // A retry is re-signed with a new timestamp, but the message id is the same.
  const second = await post(app, raw, signatureHeader(raw, { timestamp: Math.floor(Date.now() / 1000) + 5 }));
  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  assert.equal(second.body.duplicate, true);
  assert.equal(handled.length, 1);
});

test("a valid signature over a body that is not JSON is a 400", async () => {
  const { app } = harness();
  const raw = "this is not json";
  const res = await post(app, raw, signatureHeader(raw));
  assert.equal(res.status, 400);
});

test("with no secret configured nothing is accepted", async () => {
  const app = createApp({ secret: undefined, seen: new SeenIds(), onMessage: () => {} });
  const raw = delivery();
  const res = await post(app, raw, signatureHeader(raw));
  assert.equal(res.status, 500);
});
