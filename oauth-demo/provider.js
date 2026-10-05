// provider.js
// ISEC3004 Assignment 1 - Mock OAuth 2.0 Authorization Server
//
// Run: node provider.js   (listens on http://localhost:7000)
//
// This is a deliberately small, OFFLINE stand-in for an identity provider
// such as "Sign in with Google". It implements just enough of the
// Authorization Code flow for the relying-party (RP) demos to be realistic:
//
//   GET  /authorize   -> shows a consent screen, then redirects back to the
//                        RP's redirect_uri with ?code=...&state=... (the
//                        state value is echoed back untouched, exactly like a
//                        real provider does).
//   POST /token       -> the RP exchanges the one-time code for the user's
//                        profile.
//
// Using a mock provider keeps the whole demo reproducible on one machine with
// no client secrets or internet access. The session-fixation flaw being
// demonstrated lives entirely in the RELYING PARTY, not here, so a mock
// provider is a faithful substitute for the assignment.

const express = require('express');
const crypto = require('crypto');

const app = express();
const PORT = 7000;

// The end user's account AT THE PROVIDER (like their Google account). The
// password lives only here -- the relying party never sees it, which is the
// whole point of OAuth and the reason session fixation is dangerous: the
// attacker takes over the account without ever learning this password.
const PROVIDER_USER = {
  sub: 'user-001',
  username: 'alice',
  password: 'password123',
  name: 'alice',
  email: 'victim@example.com',
};

// Registered RP callback URLs. Both demo RPs are allowed.
const ALLOWED_REDIRECTS = new Set([
  'http://localhost:7001/callback', // vulnerable RP
  'http://localhost:7002/callback', // mitigated RP
]);

// Issued authorization codes: code -> { user, used }
const codes = {};

app.use(express.urlencoded({ extended: true }));

// Step 1: the RP sends the user here to authorize.
app.get('/authorize', (req, res) => {
  const { client_id, redirect_uri, state, response_type } = req.query;

  if (response_type !== 'code' || !ALLOWED_REDIRECTS.has(redirect_uri)) {
    return res.status(400).send('invalid authorization request');
  }

  // Login + consent screen. The user signs in with their PROVIDER credentials
  // (never shared with the relying party) and authorizes the app. Submitting
  // posts back to /authorize/approve with the credentials, redirect_uri and
  // state. A real "Sign in with Google" screen looks just like this.
  const error = req.query.error ? '<p style="color:#b02a37">Invalid credentials, try again.</p>' : '';
  res.send(`
    <h2>Mock OAuth Provider &mdash; Sign in</h2>
    <p>Application <b>${client_id || 'demo-client'}</b> wants to sign you in.</p>
    ${error}
    <form method="POST" action="/authorize/approve">
      <p><input name="username" placeholder="username" value="alice"></p>
      <p><input name="password" type="password" placeholder="password" value="password123"></p>
      <input type="hidden" name="redirect_uri" value="${redirect_uri}">
      <input type="hidden" name="state" value="${state || ''}">
      <button type="submit">Sign in &amp; Authorize</button>
    </form>
    <p><small>(demo credentials pre-filled: alice / password123)</small></p>
  `);
});

// Step 2: user signs in and approves -> issue a one-time code and redirect back.
app.post('/authorize/approve', (req, res) => {
  const { username, password, redirect_uri, state } = req.body;

  if (!ALLOWED_REDIRECTS.has(redirect_uri)) {
    return res.status(400).send('invalid redirect_uri');
  }

  // Authenticate the user at the provider with their provider credentials.
  if (username !== PROVIDER_USER.username || password !== PROVIDER_USER.password) {
    const back = `/authorize?response_type=code&client_id=demo-client`
      + `&redirect_uri=${encodeURIComponent(redirect_uri)}&state=${encodeURIComponent(state || '')}&error=1`;
    return res.redirect(back);
  }

  const code = crypto.randomBytes(16).toString('hex');
  codes[code] = { user: PROVIDER_USER, used: false };

  // The state value is returned to the RP UNCHANGED. It is the RP's job to
  // have generated it and to verify it on the way back.
  const url = `${redirect_uri}?code=${code}` + (state ? `&state=${encodeURIComponent(state)}` : '');
  res.redirect(url);
});

// Step 3: the RP exchanges the code for the user profile (back-channel).
app.post('/token', (req, res) => {
  const { code } = req.body;
  const record = codes[code];

  if (!record || record.used) {
    return res.status(400).json({ error: 'invalid_grant' });
  }
  record.used = true; // codes are single-use

  res.json({
    access_token: crypto.randomBytes(16).toString('hex'),
    token_type: 'Bearer',
    user: record.user,
  });
});

app.listen(PORT, () => console.log(`Mock OAuth provider listening on http://localhost:${PORT}`));
