import { randomBytes, randomInt, randomUUID } from 'node:crypto';

export const random = () => randomBytes(32).toString('base64url');

// Bounded, expiring storage. Refuse new entries at capacity rather than silently
// evicting live grants (which could otherwise make revocation incomplete).
export class Memory {
  constructor(max = 10000) { this.entries = new Map(); this.max = max; }
  sweep() {
    for (const [key, item] of this.entries) {
      if (item.until <= Date.now()) this.entries.delete(key);
    }
  }
  get(key) {
    const item = this.entries.get(key);
    if (!item || item.until <= Date.now()) { this.entries.delete(key); return undefined; }
    return item.value;
  }
  set(key, value, seconds = 3600) {
    this.sweep();
    if (!this.entries.has(key) && this.entries.size >= this.max) {
      throw Object.assign(new Error('The demo is at capacity. Please try again later.'), { status: 503 });
    }
    this.entries.set(key, { value, until: Date.now() + seconds * 1000 });
  }
  delete(key) { this.entries.delete(key); }
}

export function memoryAdapter() {
  const data = new Memory(30000);
  return class Adapter {
    constructor(model) { this.model = model; }
    key(id) { return `${this.model}:${id}`; }
    async upsert(id, payload, expiresIn) { data.set(this.key(id), structuredClone(payload), expiresIn ?? 86400); }
    async find(id) { return structuredClone(data.get(this.key(id))); }
    async destroy(id) { data.delete(this.key(id)); }
    async consume(id) {
      const payload = data.get(this.key(id));
      if (payload) payload.consumed = Math.floor(Date.now() / 1000);
    }
    async findByUid(uid) { return this.findBy('uid', uid); }
    async findByUserCode(code) { return this.findBy('userCode', code); }
    async findBy(field, value) {
      data.sweep();
      for (const [key, { value: payload }] of data.entries) {
        if (key.startsWith(`${this.model}:`) && payload[field] === value) return structuredClone(payload);
      }
    }
    async revokeByGrantId(id) {
      for (const [key, { value }] of data.entries) {
        if (value.grantId === id) data.delete(key);
      }
    }
  };
}

export class Accounts {
  constructor() { this.byGoogle = new Map(); this.bySub = new Map(); this.ids = new Set(); }
  fromGoogle(profile) {
    let account = this.byGoogle.get(profile.sub);
    if (!account) {
      if (this.ids.size >= 10000) throw Object.assign(new Error('Account capacity reached.'), { status: 503 });
      let id;
      do { id = String(randomInt(100000, 1000000)); } while (this.ids.has(id));
      this.ids.add(id);
      account = { sub: randomUUID(), current_id: id };
      this.byGoogle.set(profile.sub, account);
      this.bySub.set(account.sub, account);
    }
    Object.assign(account, {
      name: profile.name || `Current ${account.current_id}`,
      email: profile.email, email_verified: profile.email_verified === true,
    });
    return account;
  }
}
