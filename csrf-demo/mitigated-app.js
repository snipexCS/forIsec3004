// mitigated-app.js
// ISEC3004 Assignment 1 - Cross-Site Request Forgery (MITIGATED VERSION)
//
// Run: node mitigated-app.js
// Visit: http://localhost:4001/login  (demo user: alice / password123)
//
// Fix: synchronizer token pattern. A random CSRF token is generated per
// session, embedded as a hidden field in the account form, and verified
// on every state-changing POST. A forged cross-site request cannot know
// this token, so the request is rejected. The session cookie is also
// marked SameSite=Strict as defense-in-depth.

const express = require('express');
const fs = require('fs');
const { sessionMiddleware, randomId } = require('./shared-session');

const app = express();
const PORT = 4001;
const DEMO_USER = { username: 'alice', password: 'password123' };

function log(line) {
  const entry = `[${new Date().toISOString()}] ${line}`;
  console.log(entry);
  fs.appendFileSync('mitigated-csrf.log', entry + '\n');
}

app.use(express.urlencoded({ extended: true }));
app.use(sessionMiddleware);

app.use((req, res, next) => {
  log(`Request ${req.method} ${req.path} | sid=${req.sessionID} | origin=${req.headers.origin || 'none'} | referer=${req.headers.referer || 'none'} | authenticated=${req.session.authenticated}`);
  next();
});

app.get('/login', (req, res) => {
  res.send(`
    <h2>Login</h2>
    <form method="POST" action="/login">
      <input name="username" placeholder="username" value="alice">
      <input name="password" placeholder="password" type="password" value="password123">
      <button type="submit">Log in</button>
    </form>
  `);
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (username === DEMO_USER.username && password === DEMO_USER.password) {
    req.session.authenticated = true;
    req.session.user = username;
    log(`Login success for user=${username} | sid=${req.sessionID}`);
    return res.redirect('/account');
  }
  res.status(401).send('Invalid credentials');
});

app.get('/account', (req, res) => {
  if (!req.session.authenticated) return res.status(401).send('Not logged in. <a href="/login">Login</a>');

  // ---------------------------------------------------------------
  // MITIGATED: issue a per-session CSRF token and embed it as a
  // hidden field. The server will only accept the update if this
  // exact token is echoed back.
  if (!req.session.csrfToken) req.session.csrfToken = randomId();
  // ---------------------------------------------------------------

  res.send(`
    <h2>My Account</h2>
    <p>Current email: <b>${req.session.email}</b></p>
    <form method="POST" action="/account/update-email">
      <input type="hidden" name="csrf_token" value="${req.session.csrfToken}">
      <input name="newEmail" placeholder="new email">
      <button type="submit">Update email</button>
    </form>
  `);
});

app.post('/account/update-email', (req, res) => {
  if (!req.session.authenticated) return res.status(401).send('Not logged in');

  // ---------------------------------------------------------------
  // MITIGATED: verify the submitted CSRF token matches the one tied
  // to this session before performing the state-changing action. A
  // cross-site attacker cannot read the victim's page to obtain this
  // token (same-origin policy), so a forged request will fail here.
  const submittedToken = req.body.csrf_token;
  if (!submittedToken || submittedToken !== req.session.csrfToken) {
    log(`BLOCKED: invalid/missing CSRF token on update-email | sid=${req.sessionID} | origin=${req.headers.origin || 'none'} | referer=${req.headers.referer || 'none'}`);
    return res.status(403).send('Forbidden: invalid CSRF token');
  }
  // ---------------------------------------------------------------

  const { newEmail } = req.body;
  req.session.email = newEmail;
  log(`EMAIL CHANGED to ${newEmail} | sid=${req.sessionID} | csrf token verified`);
  res.send(`Email updated to ${newEmail}`);
});

app.listen(PORT, () => log(`MITIGATED CSRF app listening on http://localhost:${PORT}`));
