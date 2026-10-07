# OAuth Session Fixation Demo (ISEC3004 Assignment 1, Group 33)

A self-contained demonstration of the **OAuth Session Fixation** vulnerability:
a vulnerable relying party (RP), the exploit that achieves account takeover, a
mitigated RP, and log-based detection/tracing. Everything runs offline against a
small **mock OAuth provider**, so no real identity provider or secrets are needed.

## The vulnerability in one paragraph

After a user signs in through OAuth, the vulnerable RP **keeps the same session
ID it had before login** instead of issuing a new one. If an attacker can plant
a session ID they already know into the victim's browser *before* login (here,
via a `?sid=` link the RP wrongly honours), that same session becomes
authenticated once the victim signs in — and the attacker still holds it. The fix
is to **regenerate the session ID on authentication** (plus bind/verify the OAuth
`state` and harden the cookie).

## Components and ports

| File | Role | Port |
|------|------|------|
| `provider.js` | Mock OAuth 2.0 authorization server | 7000 |
| `vulnerable-app.js` | Relying party **without** session regeneration (the flaw) | 7001 |
| `mitigated-app.js` | Relying party **with** regeneration + `state` binding (the fix) | 7002 |
| `attacker-server.js` + `attacker-page.html` | Attacker site that fixates + proves takeover | 7050 |
| `verify.js` | Headless end-to-end check (exploit vs. secure) | — |
| `shared-session.js` | Minimal cookie session layer + `regenerateSession()` | — |

Mock provider end user: **alice / victim@example.com** (hard-coded in `provider.js`).

## Requirements

- **Node.js 18+** (the apps use the global `fetch()`), and `npm`.
- `npm install` once in this folder (installs Express).

```
cd oauth-demo
npm install
```

## A) Demonstrate the exploit (vulnerable RP)

Open **three terminals** in this folder:

```
# terminal 1 – provider
node provider.js

# terminal 2 – vulnerable relying party
node vulnerable-app.js

# terminal 3 – attacker site
node attacker-server.js
```

`attacker-server.js` prints the session id it will fixate, e.g.
`[attacker] acquired RP session id to fixate: sid=ab12…`.

Then, in a **browser (the victim)**:

1. Visit the attacker lure: `http://localhost:7050/` and click **Claim your prize**.
   (This sends you to `http://localhost:7001/login?sid=<attacker_sid>` — the fixation.)
2. On the mock provider's sign-in screen, the credentials are pre-filled
   (**alice / password123**) — click **Sign in & Authorize**. (These credentials
   stay at the provider; the relying party never sees them.)
3. You land on the vulnerable RP's `/account` as alice — a normal-looking login.

Now, as the **attacker**, visit: `http://localhost:7050/takeover`.
It replays the fixated `sid` against the RP and shows **the victim's `/account`
page (victim@example.com) with HTTP 200** — account takeover confirmed.

> Tip: run the victim steps in a normal browser and leave the attacker as
> `attacker-server.js`. They are separate processes with separate cookie stores,
> which is what keeps "attacker" and "victim" distinct.

## B) Demonstrate the fix (mitigated RP)

```
# terminal 1 – provider (if not already running)
node provider.js

# terminal 2 – mitigated relying party
node mitigated-app.js

# terminal 3 – attacker site pointed at the mitigated RP
RP=http://localhost:7002 node attacker-server.js      # PowerShell: $env:RP="http://localhost:7002"; node attacker-server.js
```

Repeat the same victim steps against `http://localhost:7002`. The victim still
logs in fine, but `http://localhost:7050/takeover` now returns **HTTP 401** — the
attacker's fixated `sid` was discarded when the session was regenerated at login.

## C) Headless verification (optional, for QA evidence)

With the provider and the relevant RP running:

```
node verify.js                              # vulnerable  -> prints ❌ EXPLOITED
RP=http://localhost:7002 node verify.js     # mitigated   -> prints ✅ SECURE
```

`verify.js` also prints whether the session id changed on login
(`NO (reused)` for the vulnerable RP, `YES (regenerated)` for the mitigated RP).

## Detection & tracing (report §2.6)

Each RP appends timestamped lines to `vulnerable-oauth.log` / `mitigated-oauth.log`.

- **Vulnerable log** — the smoking gun is a single `sid` that appears **before**
  login (planted via the `FIXATION:` line) and is still in use **after**
  `LOGIN SUCCESS (no session regeneration)`, then again on `ACCOUNT VIEWED` when
  the attacker replays it.
- **Mitigated log** — `LOGIN SUCCESS (session regenerated) | oldSid=… -> newSid=…`
  shows the identifier changing at the moment of authentication, so the planted
  id is never associated with an authenticated session. A forged callback also
  produces `BLOCKED: state mismatch on callback`.

## What to capture for the report (§2.3–§2.8)

1. **§2.3 Vulnerable code** — screenshot the `// VULNERABLE:` blocks in
   `vulnerable-app.js` (the `?sid=` sink and the callback with no regeneration).
2. **§2.4 Exploitation** — the lure page, the consent screen, the victim's
   `/account`, then `/takeover` showing HTTP 200 with the victim's email.
3. **§2.6 Detection and tracing** — the `vulnerable-oauth.log` excerpt with one
   `sid` spanning pre-login → authenticated → attacker replay.
4. **§2.7 Mitigation** — the `// MITIGATED:` blocks in `mitigated-app.js`.
5. **§2.8 Verification** — `/takeover` returning HTTP 401 against the mitigated
   RP, the `oldSid -> newSid` log line, and/or `verify.js` printing ✅ SECURE.

## Notes / scope

- The mock provider stands in for a real IdP (e.g. "Sign in with Google"). The
  assignment brief does not require a live provider; the session-fixation flaw
  lives entirely in the **relying party**, which a mock provider reproduces
  faithfully while keeping the live demo offline and repeatable.
- The session layer is hand-rolled (not `express-session`) so every step is
  visible in the logs for the report, consistent with the sibling `csrf-demo`.
