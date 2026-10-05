// mitigated-app.js
// ISEC3004 Assignment 1 - OAuth Session Fixation (MITIGATED VERSION)
//
// Run: node mitigated-app.js   (relying party on http://localhost:7002)
// Requires the mock provider (node provider.js) to be running on :7000.
// Requires Node 18+ (uses the global fetch()).
//
// Fixes applied (see the inline MITIGATED comments):
//   1. Session ID is REGENERATED the moment OAuth login succeeds, so any
//      session ID an attacker fixated before login is discarded and left
//      unauthenticated. This is the primary, decisive fix for session fixation.
//   2. The OAuth `state` parameter is generated per session, stored on the
//      session, and verified in the callback -- binding the flow to the browser
//      that started it (defence-in-depth against forged callbacks).
//   3. No "session id in the URL" sink, and the cookie is hardened with
//      HttpOnly + SameSite=Lax so it cannot be read or trivially planted.

const express = require('express');
const fs = require('fs');
const { createSessionMiddleware, regenerateSession, randomId } = require('./shared-session');

const app = express();
const PORT = 7002;
const PROVIDER = 'http://localhost:7000';
const REDIRECT_URI = `http://localhost:${PORT}/callback`;
const COOKIE_FLAGS = 'HttpOnly; SameSite=Lax';

function log(line) {
  const entry = `[${new Date().toISOString()}] ${line}`;
  console.log(entry);
  fs.appendFileSync('mitigated-oauth.log', entry + '\n');
}

app.use(express.urlencoded({ extended: true }));

// MITIGATED: no ?sid= fixation sink here -- the session ID comes only from the
// server-issued cookie, which is HttpOnly + SameSite=Lax.
app.use(createSessionMiddleware(COOKIE_FLAGS));

app.use((req, res, next) => {
  log(`Request ${req.method} ${req.path} | sid=${req.sessionID} | origin=${req.headers.origin || 'none'} | referer=${req.headers.referer || 'none'} | authenticated=${req.session.authenticated}`);
  next();
});

app.get('/', (req, res) => {
  res.send(`
    <h2>Mitigated RP</h2>
    <p>Your session id: <code>${req.sessionID}</code></p>
    <p><a href="/login">Sign in with Mock OAuth</a></p>
  `);
});

// Start the OAuth flow.
app.get('/login', (req, res) => {
  // ---------------------------------------------------------------
  // MITIGATED: generate a state value and bind it to THIS session so the
  // callback can confirm the response belongs to the flow this browser began.
  const state = randomId();
  req.session.oauthState = state;
  // ---------------------------------------------------------------
  const url = `${PROVIDER}/authorize?response_type=code&client_id=secure-rp`
    + `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&state=${state}`;
  log(`Starting OAuth | sid=${req.sessionID} | state=${state} (bound to session)`);
  res.redirect(url);
});

// OAuth callback.
app.get('/callback', async (req, res) => {
  const { code, state } = req.query;
  if (!code) return res.status(400).send('missing code');

  // ---------------------------------------------------------------
  // MITIGATED: verify the returned state matches the one tied to this session.
  if (!state || state !== req.session.oauthState) {
    log(`BLOCKED: state mismatch on callback | sid=${req.sessionID} | expected=${req.session.oauthState} | got=${state}`);
    return res.status(403).send('Forbidden: invalid OAuth state');
  }
  req.session.oauthState = null; // one-time use
  // ---------------------------------------------------------------

  const tokenRes = await fetch(`${PROVIDER}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `code=${encodeURIComponent(code)}`,
  });
  const token = await tokenRes.json();
  if (!token.user) return res.status(401).send('token exchange failed');

  req.session.authenticated = true;
  req.session.user = token.user.name;
  req.session.email = token.user.email;

  // ---------------------------------------------------------------
  // MITIGATED: regenerate the session ID now that the user is authenticated.
  // The old ID (which an attacker may have fixated) is destroyed and the
  // browser is given a fresh, server-chosen ID the attacker never saw.
  const { oldId, newId } = regenerateSession(req, res, COOKIE_FLAGS);
  // ---------------------------------------------------------------

  log(`LOGIN SUCCESS (session regenerated) | oldSid=${oldId} -> newSid=${newId} | user=${token.user.name}`);
  res.redirect('/account');
});

app.get('/account', (req, res) => {
  if (!req.session.authenticated) {
    return res.status(401).send('Not logged in. <a href="/login">Sign in</a>');
  }
  log(`ACCOUNT VIEWED | sid=${req.sessionID} | user=${req.session.user}`);
  res.send(`
    <h2>My Account</h2>
    <p>Signed in as: <b>${req.session.user}</b></p>
    <p>Email: <b>${req.session.email}</b></p>
    <p>Session id: <code>${req.sessionID}</code></p>
  `);
});

app.listen(PORT, () => log(`MITIGATED OAuth RP listening on http://localhost:${PORT}`));
