# Seattle Hookups — full-stack MVP

A real multi-user backend + mobile-first frontend for a Seattle-only,
adults-only (18+) dating/hookup app. One deployable unit: **FastAPI + SQLite**,
frontend served as static files from the same process. No external database
or services required.

**What works:** signup/login/logout (bcrypt + session cookies, 18+ enforced),
editable profiles with real Seattle neighborhoods, photo upload (up to 4,
type-checked server-side), discovery with neighborhood/age filters, like/pass,
mutual-like matching, match-only chat (polling), block, report, safety-tips page.

## Run locally

```bash
cd seattle-hookups-fullstack
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn main:app --reload --port 8000
```

Open http://localhost:8000. The SQLite DB is created automatically at
`./data/app.db` on first start (schema only — **no fake users are seeded**);
uploads go to `./uploads/`.

Optional env vars: `DB_PATH`, `UPLOAD_DIR`, `COOKIE_SECURE=1` (set this in
production — it marks the session cookie Secure/HTTPS-only), `SESSION_DAYS`.

API docs (dev only): http://localhost:8000/api/docs

## Deploy

### Render (recommended one-click)
1. Push this folder to a GitHub repo.
2. In Render: **New → Blueprint**, point it at the repo — `render.yaml`
   creates the web service **with a 1 GB persistent disk** mounted at `/data`
   (SQLite + uploads live there, so they survive redeploys).
3. Done. Your app is at `https://<service>.onrender.com`.

### Fly.io
```bash
fly launch --no-deploy        # accept the generated settings, then:
fly volumes create sh_data -r sea -s 1
fly deploy
```
`fly.toml` already points at the Seattle region, mounts the volume at `/data`,
and forces HTTPS.

### Railway
1. New project → deploy from the GitHub repo (it detects the Dockerfile).
2. Add a **volume** mounted at `/data`.
3. Set env var `COOKIE_SECURE=1`. Deploy.

> Whichever host you use: the disk/volume at `/data` is **not optional**.
> Without it, every redeploy wipes all users, matches, messages, and photos.

## Project layout

```
main.py            # entire backend: API, auth, uploads, static serving
static/
  index.html       # SPA shell (auth, discover, matches, chat, profile, safety)
  app.js           # frontend logic
  styles.css       # mobile-first, dark-friendly styling
requirements.txt   # pinned deps
Dockerfile         # single-container image
render.yaml        # Render Blueprint (service + persistent disk)
fly.toml           # Fly.io config (Seattle region + volume)
```

## OPERATING NOTES — read before opening this to the public

This software handles **real people's photos, messages, ages, and
neighborhood-level location**. Running it for actual users makes you the
operator of an adults-only dating service, with real legal and safety
responsibilities. This MVP is a technical starting point, not a
production-ready product. At minimum, sort these out **before** inviting
strangers:

1. **Real 18+ verification.** The app rejects under-18 signups by date of
   birth, but DOB is self-reported — anyone can lie. A public launch needs
   actual age verification (ID check via a provider like Veriff/Persona, or
   equivalent). Do not rely on the DOB field alone.
2. **Moderation process.** Reports are stored in the `reports` table, but
   nobody reviews them automatically — *you* need a workflow: who reads
   reports, response times, when to ban, and how to preserve evidence.
   Consider adding an admin view/ban tool before launch.
3. **Terms of Service & Privacy Policy.** Required in essentially every
   jurisdiction. Cover: 18+ only, acceptable use, photo consent (no uploading
   other people), data retention, and how to request deletion.
4. **Data deletion.** Users can currently delete photos but not their
   account. Add a "delete my account" flow (GDPR/CCPA-style requests will
   come) and a retention policy for messages/reports.
5. **Security hardening.** This MVP has basic rate limiting on auth, but a
   public launch should add: a WAF/CDN in front, login-attempt lockout,
   session anomaly detection, and regular dependency updates. Never expose
   the SQLite file or `/data` over HTTP (the app doesn't, but your host
   config must not either).
6. **Abuse vectors specific to dating apps.** Expect: catfishing/fake
   profiles, harassment, sextortion, and spam. Photo verification
   (selfie-match), phone verification, and report-rate monitoring are the
   standard mitigations — none are in this MVP.
7. **Backups.** Back up `/data` (SQLite + uploads) on a schedule and test
   restores. Losing the DB loses every account.
8. **Jurisdiction.** Washington State + federal law apply (you're targeting
   Seattle). If you charge money or run ads, additional rules kick in.
   Talk to a lawyer before monetizing.

If you can't commit to 1–4, do not open registration to the public —
keep it invite-only among people you know.
