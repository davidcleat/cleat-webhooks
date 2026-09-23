// Idempotency: remember which message ids have already been handled.
//
// Cleat posts each message once, but a delivery that fails is RETRIED on a
// backoff, so the same `data.id` can legitimately arrive twice. Handling it
// twice is your bug, not Cleat's.
//
// THIS STORE IS IN-MEMORY AND PER-PROCESS. It is here so the example runs with
// no setup. It forgets everything on restart and two instances behind a load
// balancer do not see each other's ids. In a real deployment, key on the
// message id in something durable and shared: a unique index on the id column
// in your database (insert, and treat a duplicate-key error as "already done"),
// or Redis / a key-value store with SETNX and a TTL of a day or so.

export class SeenIds {
  /**
   * @param {object} [options]
   * @param {number} [options.maxEntries] bound, so a long-running process cannot grow without limit
   * @param {number} [options.ttlMs] how long an id is remembered
   */
  constructor({ maxEntries = 10_000, ttlMs = 24 * 60 * 60 * 1000 } = {}) {
    this.maxEntries = maxEntries;
    this.ttlMs = ttlMs;
    /** @type {Map<string, number>} id -> expiry, in insertion order */
    this.entries = new Map();
  }

  has(id) {
    const expiresAt = this.entries.get(id);
    if (expiresAt === undefined) return false;
    if (expiresAt <= Date.now()) {
      this.entries.delete(id);
      return false;
    }
    return true;
  }

  /**
   * Claim an id. Returns true the first time and false on every repeat, so the
   * check and the mark cannot drift apart.
   */
  addIfNew(id) {
    if (this.has(id)) return false;
    this.entries.set(id, Date.now() + this.ttlMs);
    // Map iterates in insertion order, so the first key is the oldest.
    while (this.entries.size > this.maxEntries) {
      const oldest = this.entries.keys().next().value;
      this.entries.delete(oldest);
    }
    return true;
  }

  clear() {
    this.entries.clear();
  }
}
