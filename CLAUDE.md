# Cyber Training Academy — CTF Platform

## Project Overview
A beginner-focused Capture The Flag (CTF) web platform built for the **Cyber CTF Club** at Brookhaven National Laboratory. The platform runs as a single Flask app serving 20 progressive challenges that teach real cybersecurity skills. Students submit flags and accumulate points through a session-based scoreboard.

**Live repo:** https://github.com/TomRenzulli/CTF_GAMES  
**Handle:** Wooskii / @TomRenzulli

---

## Stack
- **Backend:** Python 3.11 / Flask 3.0.3
- **Database:** SQLite (ephemeral, `/tmp/users.db` — seeded at startup for challenge 19)
- **Container:** Docker (python:3.11-slim), orchestrated with docker-compose
- **Production:** Linode Nanode (Newark NJ) → nginx reverse proxy → Flask on `127.0.0.1:9300`
- **TLS:** Let's Encrypt via certbot --nginx
- **DNS:** Cloudflare (A record → Linode IP)

---

## Project Structure
```
BERACTF/
├── app.py                    # Main Flask app — all routes, templates, challenge logic
├── requirements.txt          # flask==3.0.3
├── Dockerfile
├── docker-compose.yml
├── .dockerignore
├── CLAUDE.md                 # This file
├── static/                   # Self-hosted JetBrains Mono (woff2) + fonts.css + OFL.txt
├── docs/                     # Help material shown on the /docs tab — drop files in here
│   ├── Beginner's Guide to Cyber & CTFs.pdf
│   ├── CTF_VM_Setup_Guide.pdf
│   ├── Think_Like_a_Hacker_CTF.pdf
│   └── What_is_a_CTF.pdf
└── challenge_files/
    ├── generate.py           # Generates all static challenge files at Docker build time
    ├── signal.txt            # Challenge 2 — hex-encoded flag
    ├── binary_message.txt    # Challenge 3 — binary-encoded flag
    ├── mystery.bin           # Challenge 6 — strings challenge
    ├── definitely_a_text_file.txt  # Challenge 7 — ZIP disguised as .txt
    ├── training_badge.png    # Challenge 14 — PNG with tEXt metadata chunk
    └── report.pdf            # Challenge 15 — JPEG disguised as .pdf
```

---

## The Challenge Ladder
Generated from the `CHALLENGES` list in `app.py` — regenerate rather than hand-editing.
Counts are derived at runtime (`TOTAL_CHALLENGES`, `CATEGORY_ORDER`), so this table is documentation, not configuration.

| # | Title | Category | Skill taught | Pts |
|---|-------|----------|--------------|-----|
| 1 | Base64 Basics | Encoding | Decoding Base64 | 50 |
| 2 | Hex Signals | Encoding | Decoding hexadecimal | 50 |
| 3 | Binary Message | Encoding | Reading binary / ASCII | 50 |
| 4 | View Source | Recon | Reading HTML page source | 75 |
| 5 | HTTP Headers | Recon | Inspecting HTTP response headers | 75 |
| 6 | Strings Search | File Analysis | Using the `strings` command | 100 |
| 7 | Wrong Extension | File Analysis | Using the `file` command / magic bytes | 100 |
| 8 | ROT13 | Crypto | ROT13 / Caesar cipher | 100 |
| 9 | Caesar Brute Force | Crypto | Brute-forcing Caesar cipher (26 shifts) | 125 |
| 10 | Cookie Monster | Web | Reading and editing browser cookies | 125 |
| 11 | URL Parameters | Web | Manipulating URL query parameters | 125 |
| 12 | robots.txt | Recon | Checking robots.txt for hidden paths | 150 |
| 13 | Directory Guessing | Recon | Discovering hidden endpoints by guessing | 150 |
| 14 | Image Metadata | Forensics | Extracting EXIF / metadata from images | 150 |
| 15 | Magic Bytes | Forensics | Identifying files by magic bytes / file header | 150 |
| 16 | Default Credentials | Auth | Testing default / common credentials | 175 |
| 17 | Weak Token | Auth | Predicting / forging weak session tokens | 175 |
| 18 | Command Injection | Injection | Basic OS command injection via shell metacharacters | 200 |
| 19 | SQL Injection | Injection | Classic SQL injection (OR 1=1) | 200 |
| 20 | Final Boss: Chain It | Chain | Multi-step: recon → decode → submit | 250 |

---

## Flag Values
Flags live in the `"flag"` field of each entry in the `CHALLENGES` list in `app.py` (challenge 18's flag is also written by the `Dockerfile`). They are deliberately not repeated here — keep answer keys out of docs.

---

## Key App Behavior

### Phishing-awareness splash (`/welcome`)
`GET /` redirects to `/welcome` until `session["warned"]` is set. The splash is a
funny-but-serious warning about not trusting URLs — the site's own domain
(`shouldiclickthislink.com`) is the teaching example — plus a verify-before-you-click
checklist and a note that the range is deliberately vulnerable.

- Entry is a **form POST button**, not a link, on purpose: the page should not end by
  rewarding a click. `POST /welcome` sets the session flag and redirects to `/`.
- **Only `/` is gated.** Challenge endpoints (`/header-challenge`, `/robots.txt`,
  `/backup`, `/ping-tool`, …) must stay reachable without the splash, or challenge 5
  (`curl -I /header-challenge`) and the other direct-URL challenges break.
- Session-scoped, so it shows once per browser session (same lifetime as the score).

### Documents tab (`/docs`)
`/docs` lists every file in the repo's `docs/` directory (`DOCS_DIR`); `/docs/<filename>`
serves it via `send_from_directory`. Titles are derived from the filename (underscores and
hyphens become spaces). **To add help material, commit a file into `docs/` and redeploy** —
no code change needed. The nav link appears in all four page headers.

### Header
The brand text in the top-left is an `<a href="/">` (`.brand` class) — the home button.
Each template carries its own copy of the header markup, so a header change means editing
all four (`HEADER_HTML` is currently unused/dead code).

### Session signing key (do not revert)
`app.secret_key` comes from `_load_secret_key()`: `CTF_SECRET_KEY` env var →
`CTF_SECRET_KEY_FILE` (default `/data/secret_key`, mode 0600) → generate and
persist. `/data` is the `ctf-state` named volume, so the key — and therefore every
student's solved challenges — survives `docker compose up -d --build`.
A per-process `secrets.token_hex()` key (the original behavior) logged everyone out
on each redeploy and would break outright under more than one worker, since each
worker would sign cookies with a different key. `docker compose down -v` destroys
the volume and the key; use plain `down`/`restart`.

### Flag grading
`grade_submission()` (not a bare `==`) handles every submission. `normalize_flag()`
strips zero-width characters, BOM, non-breaking spaces and smart quotes, collapses
whitespace and case-folds, so copy-paste artifacts never cost a student an attempt.
**Flags are case-insensitive.** Failures return a targeted message: right answer
without the `FLAG{}` wrapper, a valid flag for a different challenge, correct shape
with wrong contents, or empty input. These messages contain `<code>` tags and are
rendered with `{{ error|safe }}` on the challenge page — they are app-authored
constants and never interpolate user input. The **index** banner is fed from a
query parameter and must stay escaped.

### Instructor view (`/instructor`)
Anonymous aggregate counters only — attempts and solves per challenge plus a count
of sessions started — held in process memory under `_STATS_LOCK`, never written to
disk, reset on container restart (so the numbers cover one club meeting). Rows sort
by **failed attempts per solve**, which surfaces the challenge that's burning the
room. No identities and no submitted values are stored.

Deliberately **not** token-gated: the whole site already sits behind one shared
nginx basic-auth password and the data is anonymous aggregate. It is intentionally
**not linked from the student nav** — reachable by URL, to keep the student UI
focused. A re-submit of an already-solved challenge and an empty submission are
both excluded from the counts.

A scoreboard was considered and **deliberately rejected** — scoring stays
session-only so there is no student PII anywhere in the app.

### Startup
- `init_db()` creates `/tmp/users.db` with an `admin` and a `guest` user for challenge 19 (credentials are in `init_db()`)
- `/flag18.txt` is written at Docker build time (not at runtime)

### Scoring
- Session-based (`session['solved']` set, `session['score']` int)
- `TOTAL_POINTS` derived from the CHALLENGES list at module load
- No persistent scoreboard — refreshing resets score (intentional for a training environment)

### Challenge Data Structure
Each challenge in the `CHALLENGES` list is a dict:
```python
{
    "id": int,
    "title": str,
    "category": str,
    "skill": str,
    "story": str,          # flavor text shown to student
    "flag": str,           # correct answer
    "points": int,
    "notes": [             # 4 collapsible training notes per challenge
        ("Label", "HTML text"),
        ...
    ]
}
```

### Progressive hints
Each challenge carries `c["hints"]`: three click-to-reveal tiers rendered as native
`<details>` elements (nudge → method → exact command). Tiers 1-2 are authored in
`HINT_TIERS`; tier 3 is lifted automatically from the legacy `<b>Hint:</b>` line
that used to sit visible in the story, by `_split_inline_hint()`. **Do not put the
solution back in the story** — the always-visible command was the problem this
replaced. Hints are hidden once the challenge is solved.

### Post-solve takeaway
`TAKEAWAYS[id]` is one line shown in the solved banner, plus a prominent
`.next-cta` to the next challenge (or back to the ladder on #20), and the Training
Notes auto-expand. Solving used to display only a point total.

### Per-challenge further reading
`DOC_LINKS[id]` lists PDF filenames from `docs/`. `_prepare_challenges()` resolves
them against `DOCS_DIR` at import and drops any that don't exist, so renaming a PDF
removes the link instead of producing a dead one.

### Shared header (`SITE_HEADER`)
One header definition for all pages. `header_ctx(active, show_stats=True)` supplies
`active` (`"challenges"` | `"docs"` | `"instructor"`), the score chip values and
`total_challenges`; the active nav link gets `aria-current="page"`. The four
duplicated inline `<header>` blocks are gone — a nav change is now one edit.
`HEADER_HTML` (dead code) was replaced by this.

### Derived counts — do not hardcode
`TOTAL_CHALLENGES` and `CATEGORY_ORDER` (first-appearance order of categories) are
derived from `CHALLENGES`. The index previously hardcoded a nine-name category list,
so a challenge in a new category rendered **nowhere**; templates now take
`categories=CATEGORY_ORDER` and `total_challenges`. There are no literal `20`s left
in the templates.

### Self-hosted font
JetBrains Mono (400/700) is served from `static/fonts/` via `@font-face` in
`BASE_STYLE`, with `static/fonts.css` for the inline challenge sub-pages. **No page
requests fonts.googleapis.com any more** — the site renders identically on a
locked-down network or an offline lab VM, and no student request leaves for a third
party. Licence: SIL OFL, `static/fonts/OFL.txt` (redistribution is permitted; keep
that file).

### Copy buttons
`addCopyButtons()` on the challenge page adds a copy control to every `.block-code`
and to any inline `<code>` of 12+ characters. Progressive enhancement — with JS off
the page is unchanged. Clipboard API with a `textarea` + `execCommand` fallback for
non-HTTPS contexts.

### Collapsible Training Notes
Each challenge page has a `▶ Training Notes` section (`.notes-section` CSS class) that toggles open/closed via `toggleNotes()` JS. The 4 notes per challenge cover: concept, recognition pattern, real-world context, and tools.

---

## Docker

### Build & Run
```bash
docker compose up -d --build
```

### What happens at build time
1. `pip install -r requirements.txt`
2. `python challenge_files/generate.py` — writes all challenge files relative to its own location (uses `pathlib.Path(__file__).parent.resolve()`)
3. Writes the challenge 18 flag to `/flag18.txt`

### Port binding
- docker-compose.yml binds `"127.0.0.1:9300:9300"` — the app is only reachable through nginx. Keep it this way in production: Docker-published ports bypass `ufw`, so `"9300:9300"` would expose the intentionally vulnerable app directly on the public IP.
- Local development: `http://localhost:9300` works as-is.

---

## Deployment (Production)

### Server setup (Linode Ubuntu 24.04)
```bash
apt update && apt upgrade -y
apt install -y docker.io docker-compose-v2 git nginx certbot python3-certbot-nginx
systemctl enable --now docker
ufw allow OpenSSH && ufw allow 'Nginx Full' && ufw enable
git clone https://github.com/TomRenzulli/CTF_GAMES.git /opt/beractf   # private repo: use a read-only deploy key, not a PAT in the URL (it gets saved in .git/config)
cd /opt/beractf
docker compose up -d --build
```

### Access control (required)
Challenge 18 is a real command injection, so anyone who can reach the site can run commands in the container. Put the site behind auth:
```bash
apt install -y apache2-utils
htpasswd -c /etc/nginx/.htpasswd student   # share this password with the club
```
Or restrict by IP with `allow <club-cidr>; deny all;` in the `location` block.

### nginx config (`/etc/nginx/sites-available/beractf`)
```nginx
server {
    listen 80;
    server_name ctf.shouldiclickthislink.com;
    location / {
        auth_basic "Cyber CTF";
        auth_basic_user_file /etc/nginx/.htpasswd;
        proxy_pass http://127.0.0.1:9300;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

### TLS
```bash
certbot --nginx -d ctf.shouldiclickthislink.com
```

### Cloudflare DNS
- A record: `ctf` → Linode IP
- Proxy: **DNS only (grey cloud)** during cert issuance; optionally enable orange cloud after
- If proxied: set SSL/TLS mode to **Full (strict)**

### Pulling updates
```bash
cd /opt/beractf && git pull && docker compose up -d --build
```

---

## Favicon
- `FAVICON_SVG` in `app.py` holds an inline SVG shield (neon `#00ff9d` outline, `#2de2ff` check) — no static dir, no binary asset.
- Served at `/favicon.svg`; `/favicon.ico` 302-redirects to it so the smaller inline-HTML pages get an icon too.
- `FAVICON_LINK` is interpolated into the `<head>` of `INDEX_PAGE`, `CHALLENGE_PAGE`, and `DOCS_PAGE`.

---

## Development Notes
- `app.py` runs Flask's built-in server with `debug=False` — never turn debug on in production (the Werkzeug debugger allows code execution); consider gunicorn for heavier load
- The SQLite DB is ephemeral — it resets every time the container restarts (intentional)
- Challenge 18 uses `subprocess.run()` with shell injection — intentionally vulnerable; only expose it behind nginx auth or an IP allowlist (see Deployment)
- `generate.py` uses `pathlib` for cross-environment path resolution — do not hardcode paths
