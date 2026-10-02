// vulnerable-app.js
// ISEC3004 Assignment 1 - Cross-Site Request Forgery (VULNERABLE VERSION)
//
// Run: node vulnerable-app.js
// Visit: http://localhost:4000/login  (demo user: alice / password123)
//
// Flaw: /account/update-email changes the logged-in user's email based
// solely on a valid session cookie. It never verifies that the request
// was intentionally submitted by the user from the app's own page, so
// any site the victim's browser visits can silently trigger this request.

const express = require('express');
const fs = require('fs');
const { sessionMiddleware } = require('./shared-session');

const app = express();
const PORT = 4000;
const DEMO_USER = { username: 'alice', password: 'password123' };

function log(line) {
  const entry = `[${new Date().toISOString()}] ${line}`;
  console.log(entry);
  fs.appendFileSync('vulnerable-csrf.log', entry + '\n');
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
    <p>(demo credentials pre-filled: alice / password123)</p>
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
  res.send(`
    <h2>My Account</h2>
    <p>Current email: <b>${req.session.email}</b></p>
    <form method="POST" action="/account/update-email">
      <input name="newEmail" placeholder="new email">
      <button type="submit">Update email</button>
    </form>
  `);
});

app.post('/account/update-email', (req, res) => {
  if (!req.session.authenticated) return res.status(401).send('Not logged in');

  // ---------------------------------------------------------------
  // VULNERABLE: relies only on the session cookie for authorization.
  // No CSRF token check, no Origin/Referer verification -- any site
  // the victim's browser visits can submit this form on their behalf.
  const { newEmail } = req.body;
  req.session.email = newEmail;
  // ---------------------------------------------------------------

  log(`EMAIL CHANGED to ${newEmail} | sid=${req.sessionID} | origin=${req.headers.origin || 'none'} | referer=${req.headers.referer || 'none'}`);
  res.send(`Email updated to ${newEmail}`);
});

app.listen(PORT, () => log(`VULNERABLE CSRF app listening on http://localhost:${PORT}`));
