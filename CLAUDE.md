# BERA Cyber Training Academy — CTF Platform

## Project Overview
A beginner-focused Capture The Flag (CTF) web platform built for the **BERA Cyber CTF Club** at Brookhaven National Laboratory. The platform runs as a single Flask app serving 20 progressive challenges that teach real cybersecurity skills. Students submit flags and accumulate points through a session-based scoreboard.

**Live repo:** https://github.com/TomRenzulli/CTF_GAMES  
**Handle:** Banshee / @TomRenzulli

---

## Stack
- **Backend:** Python 3.11 / Flask 3.0.3
- **Database:** SQLite (ephemeral, `/tmp/users.db` — seeded at startup for challenge 19)
- **Container:** Docker (python:3.11-slim), orchestrated with docker-compose
- **Production:** DigitalOcean Droplet → nginx reverse proxy → Flask on `127.0.0.1:9300`
- **TLS:** Let's Encrypt via certbot --nginx
- **DNS:** Cloudflare (A record → Droplet IP)

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
| 10 | Cookie Monster | Web | Set admin=true cookie |
| 11 | Open Sesame | Web | ?access=granted URL param |
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

### Server setup (DigitalOcean Ubuntu 24.04)
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
    server_name ctf.yourdomain.com;
    location / {
        auth_basic "BERA CTF";
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
certbot --nginx -d ctf.yourdomain.com
```

### Cloudflare DNS
- A record: `ctf` → Droplet IP
- Proxy: **DNS only (grey cloud)** during cert issuance; optionally enable orange cloud after
- If proxied: set SSL/TLS mode to **Full (strict)**

### Pulling updates
```bash
cd /opt/beractf && git pull && docker compose up -d --build
```

---

## Development Notes
- `app.py` runs Flask's built-in server with `debug=False` — never turn debug on in production (the Werkzeug debugger allows code execution); consider gunicorn for heavier load
- The SQLite DB is ephemeral — it resets every time the container restarts (intentional)
- Challenge 18 uses `subprocess.run()` with shell injection — intentionally vulnerable; only expose it behind nginx auth or an IP allowlist (see Deployment)
- `generate.py` uses `pathlib` for cross-environment path resolution — do not hardcode paths
