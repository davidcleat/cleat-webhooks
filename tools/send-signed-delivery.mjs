// Send a correctly signed delivery to a local webhook receiver, so you can try
// any of these examples without waiting for a real text.
//
//   CLEAT_WEBHOOK_SECRET=whsec_test_secret \
//     node tools/send-signed-delivery.mjs http://localhost:3000/webhooks/cleat
//
// Options:
//   --type test          send the "test" event shape instead of message.received
//   --id <uuid>          reuse a message id, to see idempotency in action
//   --skew <seconds>     shift the timestamp, to see the replay guard reject it
//   --tamper             sign one body and send a different one
//
// This is a development aid. Nothing in the examples needs it.

import { createHmac, randomUUID } from "node:crypto";

const VALUE_FLAGS = new Set(["type", "id", "skew"]);
const argv = process.argv.slice(2);
const options = {};
const positional = [];
for (let i = 0; i < argv.length; i++) {
  const arg = argv[i];
  if (!arg.startsWith("--")) {
    positional.push(arg);
    continue;
  }
  const name = arg.slice(2);
  if (VALUE_FLAGS.has(name)) {
    options[name] = argv[i + 1];
    i++; // skip the value
  } else {
    options[name] = true;
  }
}

const url = positional[0] ?? "http://localhost:3000/webhooks/cleat";
const flag = (name) => options[name];

const secret = process.env.CLEAT_WEBHOOK_SECRET;
if (!secret) {
  console.error("set CLEAT_WEBHOOK_SECRET to the same value your receiver is using");
  process.exit(1);
}

const type = flag("type") === "test" ? "test" : "message.received";
const id = typeof flag("id") === "string" ? flag("id") : randomUUID();
const skew = Number(flag("skew") ?? 0);

const body = JSON.stringify({
  type,
  data: {
    id,
    line: { id: randomUUID(), phone: "13055550100", label: "work" },
    from: "32665",
    body: "Your Facebook code is 481920",
    code: "481920",
    receivedAt: new Date().toISOString(),
    service: { id: "facebook", name: "Facebook", color: "#0866FF" },
    contact: null,
    label: "Facebook",
  },
});

// The signature scheme, in full: HMAC-SHA256 over "<t>.<raw body>", hex.
const t = Math.floor(Date.now() / 1000) + skew;
const v1 = createHmac("sha256", secret).update(`${t}.${body}`, "utf8").digest("hex");

const sent = flag("tamper") ? body.replace("481920", "000000") : body;

const res = await fetch(url, {
  method: "POST",
  headers: {
    "content-type": "application/json",
    "user-agent": "Cleat-Webhooks/1.0",
    "cleat-signature": `t=${t},v1=${v1}`,
  },
  body: sent,
});

console.log(`${res.status} ${await res.text()}`);
console.log(`message id: ${id}`);
