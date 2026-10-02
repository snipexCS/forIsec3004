// shared-session.js
// Minimal hand-rolled cookie session layer (used by both vulnerable and
// mitigated CSRF demo apps) so behaviour is fully transparent for the report.

const crypto = require('crypto');
const store = {}; // sessionId -> { authenticated, user, csrfToken }

function randomId() {
  return crypto.randomBytes(16).toString('hex');
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  header.split(';').forEach(pair => {
    const [k, ...v] = pair.trim().split('=');
    if (k) out[k] = decodeURIComponent(v.join('='));
  });
  return out;
}

function sessionMiddleware(req, res, next) {
  const cookies = parseCookies(req);
  let id = cookies.sid;

  if (!id || !store[id]) {
    id = randomId();
    store[id] = { authenticated: false, user: null, csrfToken: null, email: 'victim@example.com' };
    res.setHeader('Set-Cookie', `sid=${id}; HttpOnly; Path=/`);
  }

  req.sessionID = id;
  req.session = store[id];
  next();
}

module.exports = { sessionMiddleware, store, randomId };
