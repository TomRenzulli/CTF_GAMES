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
- **Production:** Linode Nanode (Newark NJ) → nginx reverse proxy → gunicorn on `127.0.0.1:9300`
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
├── docs/                     # Help material shown on the /docs tab — drop files in here
│   └── Beginner's Guide to Cyber & CTFs.pdf
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

## The 20 Challenges (Skill Ladder)

| # | Title | Category | Mechanic |
|---|-------|----------|----------|
| 1 | The Encoded Message | Encoding | Base64 decode |
| 2 | Signal Intercept | Encoding | Hex decode of signal.txt |
| 3 | Binary Transmission | Encoding | Binary → ASCII of binary_message.txt |
| 4 | Hidden in Plain Sight | Recon | HTML comment in page source |
| 5 | The Invisible Header | Recon | X-Flag HTTP response header |
| 6 | Strings Attached | File Analysis | strings on mystery.bin |
| 7 | What's in a Name? | File Analysis | file command on ZIP named .txt |
| 8 | Caesar's Secret | Crypto | ROT13 decode |
| 9 | Shift Happens | Crypto | Caesar brute-force |
| 10 | Cookie Monster | Web | Set `role=admin` cookie |
| 11 | Open Sesame | Web | `?user=admin` URL param |
| 12 | The Forbidden Path | Recon | robots.txt |
| 13 | The Backup | Recon | Directory guess → /backup |
| 14 | Picture This | Forensics | PNG tEXt metadata chunk |
| 15 | Magic Bytes | File Analysis | JPEG magic bytes in .pdf |
| 16 | Default Danger | Web | admin/admin default creds |
| 17 | Token Trouble | Web | base64('admin') token |
| 18 | Shell Shock | Injection | Command injection → /flag18.txt |
| 19 | SQL Injection | Injection | SQLi bypass on login form |
| 20 | The Final Boss | Chained | robots → base64 → ?key=banshee |

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

### Collapsible Training Notes
Each challenge page has a `▶ Training Notes` section (`.notes-section` CSS class) that toggles open/closed via `toggleNotes()` JS. The 4 notes per challenge cover: concept, recognition pattern, real-world context, and tools.

---

## Security Posture

This app is **deliberately vulnerable** — that is the product. So a security review has
to separate three things, and anyone scanning this repo should read this first.

### 1. Intentional vulnerabilities — do NOT "fix" these
Challenges 10–20 are the curriculum: `shell=True` command injection (ch18), string-built
SQL (ch19), cookie-based auth (ch10), URL-param authorization (ch11), guessable tokens
(ch17), default creds (ch16), secrets in headers/comments/robots.txt. The injection sites
carry `# nosec` markers with a reason so that real findings don't drown in scanner noise.
**If a scanner flags one of these, that's the scanner working correctly.** Add a
suppression, don't patch the lesson.

### 2. Containment — how the intentional RCE is made survivable
Challenge 18 gives anyone who reaches the site code execution in the container. The app
can't be made safe, so the blast radius is capped at the container boundary in
`docker-compose.yml`: non-root user, `read_only` root filesystem, `cap_drop: [ALL]`,
`no-new-privileges`, `pids_limit`, `mem_limit`/`memswap_limit`, `cpus`, capped logs.
`/tmp` and `/dev/shm` are tmpfs because the app and gunicorn need to write there.

**Egress blocking is not in compose and must be done on the host** — without it that
shell can mine crypto, scan third parties from your IP, or pull a second stage:
```bash
# adjust the subnet to the actual bridge: docker network inspect bridge
iptables -I DOCKER-USER -s 172.17.0.0/16 ! -d 172.17.0.0/16 -j DROP
apt install -y iptables-persistent && netfilter-persistent save
```
This is also the right fix for the ufw-bypass problem: Docker writes its own iptables
rules, so `DOCKER-USER` is the chain that actually governs container traffic.

The app needs **zero** outbound connectivity — the Google Fonts `<link>` tags are fetched
by the student's browser, not the server.

### 3. Real defects — these get fixed normally
Anything not serving a challenge is an ordinary bug. Fixed so far: reflected XSS in
`/param-challenge` (escaped on output; the ch11 trust decision is untouched), unpinned
transitive dependencies, Flask's dev server in production, missing session cookie flags.

### Deliberate non-goals
- **No CSRF protection.** It would require `flask-wtf` across every form, including the
  intentionally-vulnerable ones, to prevent someone submitting a flag on another player's
  behalf. Not worth the complexity here — but it would make a good future challenge.
- **No CSP.** The templates are heavily inline-styled, so a real CSP needs
  `unsafe-inline`, which buys little. HSTS and the cheap headers belong at nginx.
- **No persistent scoreboard.** Session-based by design (see Scoring).

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
    # Cheap response headers. Challenge 5's own training notes teach that the
    # absence of these is a pentest finding, so the platform should set them.
    # No CSP: the templates are inline-styled (see Deliberate non-goals).
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Referrer-Policy no-referrer always;
    # certbot adds the TLS block; add HSTS only once HTTPS is confirmed working.
    # add_header Strict-Transport-Security "max-age=31536000" always;

    client_max_body_size 1m;

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

### Block container egress (required — see Security Posture)
```bash
iptables -I DOCKER-USER -s 172.17.0.0/16 ! -d 172.17.0.0/16 -j DROP
apt install -y iptables-persistent && netfilter-persistent save
```

### Pulling updates
```bash
sudo -i                 # not `sudo git pull` — the repo is root-owned, and sudo
                        # alone leaves HOME wrong, which trips git's
                        # safe.directory ownership check
cd /opt/beractf && git pull && docker compose up -d --build
```

### Post-deploy smoke test
```bash
curl -sI https://ctf.shouldiclickthislink.com/ | head -1          # 302 -> /welcome
curl -s  https://ctf.shouldiclickthislink.com/welcome | grep -c shouldiclick
```
Then in a browser: splash appears, button enters, brand links home, `/docs` lists files,
and **challenge 18 still executes** (`cap_drop: [ALL]` removes CAP_NET_RAW, so if
`iputils-ping` is present `ping` itself stops resolving — the injection still works,
which is what the challenge actually tests).

---

## Development Notes
- Served by **gunicorn** (2 workers, 4 threads) via the Dockerfile `CMD`; `app.run()` at the
  bottom of `app.py` is for local `python app.py` only. `--worker-tmp-dir /dev/shm` is
  required because the root filesystem is read-only. Never enable Flask debug mode in
  production — the Werkzeug debugger allows code execution.
- Two optional env vars: `CTF_SECRET_KEY` (stable session signing key — set it so a
  redeploy doesn't wipe every player's score mid-event) and `CTF_COOKIE_SECURE=1` (marks
  the session cookie Secure; enable in production, leave off for local HTTP).
- The SQLite DB is ephemeral — it resets every time the container restarts (intentional)
- Challenge 18 uses `subprocess.run()` with shell injection — intentionally vulnerable; only expose it behind nginx auth or an IP allowlist (see Deployment)
- `generate.py` uses `pathlib` for cross-environment path resolution — do not hardcode paths
