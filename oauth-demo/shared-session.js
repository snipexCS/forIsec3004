// shared-session.js
// Minimal hand-rolled cookie session layer (used by both the vulnerable and
// mitigated OAuth relying-party apps) so the session behaviour is fully
// transparent for the report. Adapted from ../csrf-demo/shared-session.js.
//
// The one piece that matters for the OAuth Session Fixation demo is whether
// the application REGENERATES the session identifier when a user successfully
// authenticates. The vulnerable app never calls regenerateSession(); the
// mitigated app calls it right after the OAuth callback succeeds.

const crypto = require('crypto');
const store = {}; // sessionId -> { authenticated, user, email, oauthState }

function randomId() {
  return crypto.randomBytes(16).toString('hex');
}

function newSession() {
  return { authenticated: false, user: null, email: null, oauthState: null };
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

// Basic cookie-based session middleware. `cookieFlags` lets the mitigated app
// harden the cookie (HttpOnly; SameSite=Lax) while the vulnerable app uses a
// bare cookie that is easy to fixate.
function createSessionMiddleware(cookieFlags) {
  return function sessionMiddleware(req, res, next) {
    const cookies = parseCookies(req);
    let id = cookies.sid;

    if (!id || !store[id]) {
      id = randomId();
      store[id] = newSession();
      res.setHeader('Set-Cookie', `sid=${id}; Path=/${cookieFlags ? '; ' + cookieFlags : ''}`);
    }

    req.sessionID = id;
    req.session = store[id];
    next();
  };
}

// Issue a brand-new session ID, carry over the (now authenticated) state, and
// destroy the old ID so any copy an attacker fixated earlier becomes useless.
// This is the primary fix for session fixation.
function regenerateSession(req, res, cookieFlags) {
  const oldId = req.sessionID;
  const newId = randomId();
  store[newId] = { ...store[oldId] };
  delete store[oldId];
  req.sessionID = newId;
  req.session = store[newId];
  res.setHeader('Set-Cookie', `sid=${newId}; Path=/${cookieFlags ? '; ' + cookieFlags : ''}`);
  return { oldId, newId };
}

module.exports = {
  store,
  randomId,
  newSession,
  parseCookies,
  createSessionMiddleware,
  regenerateSession,
};
