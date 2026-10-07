// vulnerable-app.js
// ISEC3004 Assignment 1 - OAuth Session Fixation (VULNERABLE VERSION)
//
// Run: node vulnerable-app.js   (relying party on http://localhost:7001)
// Requires the mock provider (node provider.js) to be running on :7000.
// Requires Node 18+ (uses the global fetch()).
//
// Flaw: this relying party (RP) has TWO weaknesses that together enable an
// OAuth session-fixation account takeover:
//   1. It adopts a session ID handed to it in the URL (?sid=...), so an
//      attacker can plant a session ID they already know into the victim's
//      browser BEFORE the victim logs in.
//   2. It NEVER regenerates the session ID when the OAuth login succeeds, and
//      it does not bind/verify the OAuth `state` parameter to the browser
//      session. So the pre-login session ID stays valid afterwards -- and the
//      attacker still knows it.
// Result: after the victim signs in with OAuth, the attacker's copy of the
// session ID is now an authenticated session belonging to the victim.

const express = require('express');
const fs = require('fs');
const { createSessionMiddleware } = require('./shared-session');

const app = express();
const PORT = 7001;
const PROVIDER = 'http://localhost:7000';
const REDIRECT_URI = `http://localhost:${PORT}/callback`;

function log(line) {
  const entry = `[${new Date().toISOString()}] ${line}`;
  console.log(entry);
  fs.appendFileSync('vulnerable-oauth.log', entry + '\n');
}

app.use(express.urlencoded({ extended: true }));

// ---------------------------------------------------------------
// VULNERABLE fixation sink: honour a session id supplied in the URL.
// A real app might do this via a "session in the URL" misconfiguration or a
// permissive cookie. It lets an attacker pin a known session ID onto the
// victim's browser before authentication.
app.use((req, res, next) => {
  if (req.query.sid) {
    req.headers.cookie = `sid=${req.query.sid}`;
    res.setHeader('Set-Cookie', `sid=${req.query.sid}; Path=/`);
    log(`FIXATION: session id taken from URL -> sid=${req.query.sid}`);
  }
  next();
});
// ---------------------------------------------------------------

// Bare cookie (no HttpOnly / SameSite) -- part of what makes fixation easy.
app.use(createSessionMiddleware(null));

app.use((req, res, next) => {
  log(`Request ${req.method} ${req.path} | sid=${req.sessionID} | origin=${req.headers.origin || 'none'} | referer=${req.headers.referer || 'none'} | authenticated=${req.session.authenticated}`);
  next();
});

app.get('/', (req, res) => {
  res.send(`
    <h2>Vulnerable RP</h2>
    <p>Your session id: <code>${req.sessionID}</code></p>
    <p><a href="/login">Sign in with Mock OAuth</a></p>
  `);
});

// Start the OAuth flow: redirect the user to the provider's /authorize.
app.get('/login', (req, res) => {
  // A state value is generated but -- VULNERABLE -- it is never stored on the
  // session nor verified in the callback, so it provides no protection.
  const state = Math.random().toString(36).slice(2);
  const url = `${PROVIDER}/authorize?response_type=code&client_id=vuln-rp`
    + `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&state=${state}`;
  log(`Starting OAuth | sid=${req.sessionID} | state=${state} (not bound to session)`);
  res.redirect(url);
});

// OAuth callback: exchange the code and mark THIS session authenticated.
app.get('/callback', async (req, res) => {
  const { code, state } = req.query;
  if (!code) return res.status(400).send('missing code');

  // VULNERABLE: the returned `state` is ignored -- no verification at all.
  const tokenRes = await fetch(`${PROVIDER}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `code=${encodeURIComponent(code)}`,
  });
  const token = await tokenRes.json();
  if (!token.user) return res.status(401).send('token exchange failed');

  // ---------------------------------------------------------------
  // VULNERABLE: the session is marked authenticated but its ID is left
  // unchanged. Whatever session ID the browser arrived with (possibly one an
  // attacker fixated via ?sid=) is now a fully authenticated session.
  req.session.authenticated = true;
  req.session.user = token.user.name;
  req.session.email = token.user.email;
  // ---------------------------------------------------------------

  log(`LOGIN SUCCESS (no session regeneration) | sid=${req.sessionID} | user=${token.user.name} | state_returned=${state}`);
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

app.listen(PORT, () => log(`VULNERABLE OAuth RP listening on http://localhost:${PORT}`));
