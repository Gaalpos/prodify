/* Prodify Cloud: sync storage for Prodify Plus (Cloudflare Worker + D1 + R2).
   The app encrypts everything before upload (contents and names), so this server only ever handles opaque bytes.
   It signs people in with an emailed code, keeps each user's objects with a revision number for safe concurrent
   edits, tells devices what changed since they last looked, and enforces the storage of each plan. */

const MB = 1024 * 1024, GB = 1024 * MB;
const PLANS = { free: 100 * MB, basic: 5 * GB, pro: 50 * GB };
const MAX_OBJECT = 25 * MB;
const CODE_TTL = 10 * 60 * 1000, CODE_TRIES = 5, CODE_GAP = 60 * 1000;
const ID_RX = /^(account|r\/[0-9a-f]{32}|a\/[A-Za-z0-9._-]{1,200})$/;
const EMAIL_RX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// The app calls from tauri://localhost, http://tauri.localhost or a browser; sessions use a bearer token, not cookies.
const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, PUT, POST, DELETE, OPTIONS',
  'access-control-allow-headers': 'authorization, content-type, if-match, x-admin-secret',
  'access-control-expose-headers': 'x-rev',
};
const json = (body, status = 200, headers = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...CORS, ...headers } });
const fail = (status, error, extra = {}) => json({ error, ...extra }, status);

const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
const sha = async (text) => hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)));
const random = (n) => hex(crypto.getRandomValues(new Uint8Array(n)));
const code6 = () => String(crypto.getRandomValues(new Uint32Array(1))[0] % 1000000).padStart(6, '0');

const me = (u) => ({ email: u.email, plan: u.plan, used: u.used, quota: PLANS[u.plan] || PLANS.free, seq: u.seq });

async function sendCode(env, email, code) {
  if (!env.RESEND_API_KEY) throw new Error('Email sending is not set up (RESEND_API_KEY)');
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { authorization: `Bearer ${env.RESEND_API_KEY}`, 'content-type': 'application/json' },
    body: JSON.stringify({
      from: env.MAIL_FROM || 'Prodify <onboarding@resend.dev>',
      to: [email],
      subject: `${code} is your Prodify code`,
      text: `Your Prodify sign-in code is ${code}\n\nIt expires in 10 minutes. If you didn't ask for it, you can ignore this email.`,
    }),
  });
  if (!res.ok) throw new Error(`Could not send the email (${res.status})`);
}

// POST /auth/start {email}: emails a 6-digit code (in local development it's returned instead).
async function authStart(req, env) {
  const { email: raw } = await req.json().catch(() => ({}));
  const email = String(raw || '').trim().toLowerCase();
  if (!EMAIL_RX.test(email) || email.length > 254) return fail(400, 'That email doesn’t look right');
  const now = Date.now();
  const prev = await env.DB.prepare('SELECT created FROM codes WHERE email = ?').bind(email).first();
  if (prev && now - prev.created < CODE_GAP) return fail(429, 'Please wait a minute before asking for another code');
  const code = code6();
  await env.DB.prepare('INSERT OR REPLACE INTO codes (email, code_hash, expires, tries, created) VALUES (?, ?, ?, 0, ?)')
    .bind(email, await sha(email + ':' + code), now + CODE_TTL, now).run();
  if (env.DEV === '1') return json({ ok: true, devCode: code });
  await sendCode(env, email, code);
  return json({ ok: true });
}

// POST /auth/verify {email, code, device}: signs in (creating the user on first sign-in) and returns a session token.
async function authVerify(req, env) {
  const body = await req.json().catch(() => ({}));
  const email = String(body.email || '').trim().toLowerCase(), code = String(body.code || '').replace(/\D/g, '');
  const row = await env.DB.prepare('SELECT * FROM codes WHERE email = ?').bind(email).first();
  const now = Date.now();
  if (!row || row.expires < now || row.tries >= CODE_TRIES) return fail(401, 'That code has expired. Ask for a new one.');
  if ((await sha(email + ':' + code)) !== row.code_hash) {
    await env.DB.prepare('UPDATE codes SET tries = tries + 1 WHERE email = ?').bind(email).run();
    return fail(401, 'That code isn’t right');
  }
  await env.DB.prepare('DELETE FROM codes WHERE email = ?').bind(email).run();
  let user = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();
  if (!user) {
    await env.DB.prepare('INSERT INTO users (id, email, created) VALUES (?, ?, ?)').bind(random(16), email, now).run();
    user = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();
  }
  const token = random(32);
  await env.DB.prepare('INSERT INTO sessions (token_hash, user_id, device, created, last_used) VALUES (?, ?, ?, ?, ?)')
    .bind(await sha(token), user.id, String(body.device || '').slice(0, 80), now, now).run();
  return json({ token, me: me(user) });
}

async function signedIn(req, env) {
  const m = (req.headers.get('authorization') || '').match(/^Bearer ([0-9a-f]{64})$/);
  if (!m) return null;
  const h = await sha(m[1]);
  const user = await env.DB.prepare('SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?').bind(h).first();
  if (user) await env.DB.prepare('UPDATE sessions SET last_used = ? WHERE token_hash = ?').bind(Date.now(), h).run();
  return user ? { user, tokenHash: h } : null;
}

// GET /changes?since=N: objects changed after seq N, oldest first (up to 1000 at a time).
async function changes(url, env, user) {
  const since = Math.max(0, parseInt(url.searchParams.get('since') || '0', 10) || 0);
  const { results } = await env.DB.prepare('SELECT id, rev, size, deleted, seq FROM objects WHERE user_id = ? AND seq > ? ORDER BY seq LIMIT 1000')
    .bind(user.id, since).all();
  const seq = results.length ? results[results.length - 1].seq : Math.max(since, 0);
  return json({ items: results, seq, more: results.length === 1000, me: me(user) });
}

async function getObject(env, user, id) {
  const row = await env.DB.prepare('SELECT rev, deleted FROM objects WHERE user_id = ? AND id = ?').bind(user.id, id).first();
  if (!row || row.deleted) return fail(404, 'Not found');
  const obj = await env.BLOBS.get(`${user.id}/${id}`);
  if (!obj) return fail(404, 'Not found');
  return new Response(obj.body, { headers: { 'content-type': 'application/octet-stream', 'x-rev': String(row.rev), ...CORS } });
}

// PUT /obj/<id> with If-Match: <rev the device last saw> (0 for a new object). A stale rev gets 409 and the
// current rev, so the device fetches, merges and tries again instead of overwriting someone else's change.
async function putObject(req, env, user, id) {
  const want = parseInt(req.headers.get('if-match') || '-1', 10);
  const row = await env.DB.prepare('SELECT rev, size, deleted FROM objects WHERE user_id = ? AND id = ?').bind(user.id, id).first();
  const cur = row ? row.rev : 0;
  if (want !== cur) return fail(409, 'Changed on another device', { rev: cur });
  const body = await req.arrayBuffer();
  if (body.byteLength > MAX_OBJECT) return fail(413, 'That file is too large for cloud sync', { max: MAX_OBJECT });
  const quota = PLANS[user.plan] || PLANS.free, old = row && !row.deleted ? row.size : 0;
  const used = user.used - old + body.byteLength;
  if (body.byteLength > old && used > quota) return fail(413, 'Your cloud storage is full', { quota: 'full', used: user.used, limit: quota });
  await env.BLOBS.put(`${user.id}/${id}`, body);
  const now = Date.now(), rev = cur + 1;
  await env.DB.batch([
    env.DB.prepare('UPDATE users SET seq = seq + 1, used = ? WHERE id = ?').bind(Math.max(0, used), user.id),
    env.DB.prepare(`INSERT INTO objects (user_id, id, rev, size, deleted, seq, updated) VALUES (?, ?, ?, ?, 0, (SELECT seq FROM users WHERE id = ?), ?)
      ON CONFLICT (user_id, id) DO UPDATE SET rev = excluded.rev, size = excluded.size, deleted = 0, seq = excluded.seq, updated = excluded.updated`)
      .bind(user.id, id, rev, body.byteLength, user.id, now),
  ]);
  return json({ rev });
}

// DELETE /obj/<id> with If-Match: leaves a tombstone (so other devices delete it too) and frees the space.
async function deleteObject(req, env, user, id) {
  const want = parseInt(req.headers.get('if-match') || '-1', 10);
  const row = await env.DB.prepare('SELECT rev, size, deleted FROM objects WHERE user_id = ? AND id = ?').bind(user.id, id).first();
  if (!row || row.deleted) return json({ rev: row ? row.rev : 0 });
  if (want !== row.rev) return fail(409, 'Changed on another device', { rev: row.rev });
  await env.BLOBS.delete(`${user.id}/${id}`);
  const rev = row.rev + 1;
  await env.DB.batch([
    env.DB.prepare('UPDATE users SET seq = seq + 1, used = MAX(0, used - ?) WHERE id = ?').bind(row.size, user.id),
    env.DB.prepare('UPDATE objects SET rev = ?, size = 0, deleted = 1, seq = (SELECT seq FROM users WHERE id = ?), updated = ? WHERE user_id = ? AND id = ?')
      .bind(rev, user.id, Date.now(), user.id, id),
  ]);
  return json({ rev });
}

// POST /admin/plan {email, plan}: sets someone's plan by hand until payments are connected.
async function adminPlan(req, env) {
  if (!env.ADMIN_SECRET || req.headers.get('x-admin-secret') !== env.ADMIN_SECRET) return fail(403, 'Forbidden');
  const { email, plan } = await req.json().catch(() => ({}));
  if (!PLANS[plan]) return fail(400, 'Plan must be free, basic or pro');
  const r = await env.DB.prepare('UPDATE users SET plan = ? WHERE email = ?').bind(plan, String(email || '').toLowerCase()).run();
  return r.meta.changes ? json({ ok: true }) : fail(404, 'No such user');
}

export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
    const url = new URL(req.url), p = url.pathname;
    try {
      if (p === '/' && req.method === 'GET') return json({ service: 'Prodify Cloud', ok: true });
      if (p === '/auth/start' && req.method === 'POST') return await authStart(req, env);
      if (p === '/auth/verify' && req.method === 'POST') return await authVerify(req, env);
      if (p === '/admin/plan' && req.method === 'POST') return await adminPlan(req, env);
      const s = await signedIn(req, env);
      if (!s) return fail(401, 'Please sign in again');
      if (p === '/me' && req.method === 'GET') return json(me(s.user));
      if (p === '/auth/logout' && req.method === 'POST') {
        await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(s.tokenHash).run();
        return json({ ok: true });
      }
      if (p === '/changes' && req.method === 'GET') return await changes(url, env, s.user);
      if (p.startsWith('/obj/')) {
        const id = decodeURIComponent(p.slice(5));
        if (!ID_RX.test(id)) return fail(400, 'Bad object id');
        if (req.method === 'GET') return await getObject(env, s.user, id);
        if (req.method === 'PUT') return await putObject(req, env, s.user, id);
        if (req.method === 'DELETE') return await deleteObject(req, env, s.user, id);
      }
      return fail(404, 'Not found');
    } catch (e) {
      return fail(500, String((e && e.message) || e));
    }
  },
};
