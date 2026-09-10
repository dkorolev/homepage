import { timingSafeEqual } from 'node:crypto';
import { parseCookie } from 'cookie';
import { Memory, random } from './memory.js';

export function sessions() {
  const store = new Memory();
  const middleware = (req, res, next) => {
    const name = req.secure ? '__Host-current-demo' : 'current-demo';
    const key = parseCookie(req.headers.cookie || '')[name];
    let session = key && store.get(key);
    if (session && session.origin !== req.demoOrigin) session = undefined;
    req.rotateSession = () => {
      if (req.sessionId) store.delete(req.sessionId);
      req.sessionId = random();
      store.set(req.sessionId, req.demoSession, 3600);
      res.cookie(name, req.sessionId, { httpOnly: true, secure: req.secure, sameSite: 'lax', path: '/', maxAge: 3600000 });
    };
    req.sessionId = key;
    req.demoSession = session || { origin: req.demoOrigin, csrf: random(), pending: new Map() };
    if (!session) req.rotateSession();
    next();
  };
  const destroy = (req, res) => {
    const name = req.secure ? '__Host-current-demo' : 'current-demo';
    const key = parseCookie(req.headers.cookie || '')[name];
    if (key && store.get(key)?.origin === req.demoOrigin) store.delete(key);
    res.clearCookie(name, { httpOnly: true, secure: req.secure, sameSite: 'lax', path: '/' });
  };
  return { middleware, destroy };
}

export function csrf(req, res, next) {
  const expected = Buffer.from(req.demoSession.csrf);
  const actual = Buffer.from(typeof req.body?.csrf === 'string' ? req.body.csrf : '');
  if (req.get('origin') && req.get('origin') !== req.demoOrigin) return res.status(403).send('Invalid origin.');
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return res.status(403).send('Invalid form token. Reload the page.');
  next();
}

export function beginFlow(req, details) {
  for (const [key, value] of req.demoSession.pending) {
    if (value.until < Date.now()) req.demoSession.pending.delete(key);
  }
  if (req.demoSession.pending.size >= 8) throw Object.assign(new Error('Too many sign-in attempts. Wait a few minutes.'), { status: 429 });
  const state = random();
  req.demoSession.pending.set(state, { ...details, until: Date.now() + 600000 });
  return state;
}

export function finishFlow(req, type) {
  const state = req.query.state;
  const pending = typeof state === 'string' && req.demoSession.pending.get(state);
  req.demoSession.pending.delete(state);
  if (!pending || pending.type !== type || pending.until <= Date.now()) {
    throw Object.assign(new Error('This sign-in expired or belongs to another browser. Start again.'), { status: 400 });
  }
  return pending;
}
