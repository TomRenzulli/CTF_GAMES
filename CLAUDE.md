# Cyber Training Academy — CTF Platform

## Project Overview
A beginner-focused Capture The Flag (CTF) web platform built for the **Cyber CTF Club**. The platform runs as a single Flask app serving progressive challenges that teach real cybersecurity skills.

Challenge scenarios use fictional organisations only — `contoso.com` for the corporate domain and `plant.local` for the internal network. Do not introduce a real organisation's name or domain into challenge content, documents or commit messages. Students submit flags and accumulate points through a session-based scoreboard.

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
├── games/                    # Self-contained HTML learning games for the /games tab (e.g. dockpunch.html)
├── docs_src/                 # HTML+CSS sources for the quick-reference PDFs (regenerate, don't re-author)
│   ├── Beginner's Guide to Cyber & CTFs.pdf
│   ├── CTF_VM_Setup_Guide.pdf
│   ├── Think_Like_a_Hacker_CTF.pdf
│   └── What_is_a_CTF.pdf
└── challenge_files/
    ├── generate.py           # Generates all static challenge files at Docker build time
    ├── pcapgen.py            # Dependency-free pcap writer (no scapy) used by generate.py
    ├── signal.txt            # Challenge 2 — hex-encoded flag
    ├── binary_message.txt    # Challenge 3 — binary-encoded flag
    ├── mystery.bin           # Challenge 6 — strings challenge
    ├── definitely_a_text_file.txt  # Challenge 7 — ZIP disguised as .txt
    ├── training_badge.png    # Challenge 14 — PNG with tEXt metadata chunk
    └── report.pdf            # Challenge 15 — JPEG disguised as .pdf
```

---

## Tracks
Challenges are grouped into tracks (`module` on each challenge; `MODULES` defines them).
`/` is the track picker, `/module/<slug>` is a track's challenge grid.

| Track | Challenges | Points | Focus |
|-------|-----------:|-------:|-------|
| 🎓 CTF Foundations | 20 | 2575 | Encoding, recon, file analysis, crypto, web, auth and injection. Builds the vocabulary every other track assumes. |
| 🌐 Network Traffic Analysis | 4 | 675 | Read real packet captures in Wireshark: harvest cleartext credentials, reassemble TCP streams, decode DNS exfiltration, read a port scan. |
| 📊 Log Analysis & Detection | 4 | 675 | The blue-team track. Find the one success in a brute force, the 200 among the 404s, impossible travel, and evidence an attacker tried to destroy. |
| 📧 Phishing & Email Forensics | 4 | 675 | Triage real .eml files: trace Received hops to the true origin, read SPF/DKIM/DMARC, unmask deceptive links, decode attachments safely. |
| 🔌 Networking 101 | 6 | 600 | Fundamentals the other tracks assume: subnet/broadcast math, CIDR host counts, public vs private (RFC 1918), well-known ports, routing tables, DNS resolution order. All data is inline — no downloads. |
| 🔧 Troubleshooting 101 | 6 | 775 | Diagnose a fault from real command output: dead link (NO-CARRIER), DNS vs connectivity, wrong subnet mask, missing default route, duplicate IP, firewall silently dropping a traceroute. Data inline. |

## The Challenge Ladder
Generated from the `CHALLENGES` list in `app.py` — regenerate rather than hand-editing.
Counts are derived at runtime (`TOTAL_CHALLENGES`, `CATEGORY_ORDER`), so this table is documentation, not configuration.

### 🎓 CTF Foundations
| # | Title | Category | Skill taught | Pts |
|---|-------|----------|--------------|-----|
|1|Base64 Basics|Encoding|Decoding Base64|50|
|2|Hex Signals|Encoding|Decoding hexadecimal|50|
|3|Binary Message|Encoding|Reading binary / ASCII|50|
|4|View Source|Recon|Reading HTML page source|75|
|5|HTTP Headers|Recon|Inspecting HTTP response headers|75|
|6|Strings Search|File Analysis|Using the `strings` command|100|
|7|Wrong Extension|File Analysis|Using the `file` command / magic bytes|100|
|8|ROT13|Crypto|ROT13 / Caesar cipher|100|
|9|Caesar Brute Force|Crypto|Brute-forcing Caesar cipher (26 shifts)|125|
|10|Cookie Monster|Web|Reading and editing browser cookies|125|
|11|URL Parameters|Web|Manipulating URL query parameters|125|
|12|robots.txt|Recon|Checking robots.txt for hidden paths|150|
|13|Directory Guessing|Recon|Discovering hidden endpoints by guessing|150|
|14|Image Metadata|Forensics|Extracting EXIF / metadata from images|150|
|15|Magic Bytes|Forensics|Identifying files by magic bytes / file header|150|
|16|Default Credentials|Auth|Testing default / common credentials|175|
|17|Weak Token|Auth|Predicting / forging weak session tokens|175|
|18|Command Injection|Injection|Basic OS command injection via shell metacharacters|200|
|19|SQL Injection|Injection|Classic SQL injection (OR 1=1)|200|
|20|Final Boss: Chain It|Chain|Multi-step: recon → decode → submit|250|

### 🌐 Network Traffic Analysis
| # | Title | Category | Skill taught | Pts |
|---|-------|----------|--------------|-----|
|21|Cleartext Credentials|Traffic Analysis|Finding credentials in unencrypted traffic|150|
|22|Stream Reassembly|Traffic Analysis|Reassembling data split across TCP segments|150|
|23|DNS Exfiltration|Exfiltration|Spotting and decoding data smuggled through DNS|200|
|24|Scan Signatures|Network Recon|Recognising a port scan and what the attacker found|175|

### 📊 Log Analysis & Detection
| # | Title | Category | Skill taught | Pts |
|---|-------|----------|--------------|-----|
|25|Brute Force in the Logs|Authentication Logs|Finding the successful login inside a brute-force attack|150|
|26|Reading Status Codes|Web Logs|Finding the request that worked in a web access log|150|
|27|Impossible Travel|Authentication Logs|Detecting account compromise from session geography|175|
|28|The Log That Remembers|Anti-Forensics|Recovering evidence an attacker tried to destroy|200|

### 📧 Phishing & Email Forensics
| # | Title | Category | Skill taught | Pts |
|---|-------|----------|--------------|-----|
|29|Following the Hops|Email Headers|Tracing an email's true origin through Received headers|150|
|30|When Everything Fails|Email Headers|Reading SPF, DKIM and DMARC results|175|
|31|Hover Before You Click|Social Engineering|Separating link text from link destination|150|
|32|Decoding the Attachment|Malware Delivery|Extracting and decoding a MIME attachment safely|200|

### 🔌 Networking 101
| # | Title | Category | Skill taught | Pts |
|---|-------|----------|--------------|-----|
|33|Subnet & Broadcast|Addressing|Network vs broadcast address of a subnet|75|
|34|CIDR Host Math|Addressing|Counting usable hosts in a CIDR block|100|
|35|Public vs Private|Addressing|Recognising RFC 1918 private ranges|100|
|36|Know Your Ports|Protocols|Mapping listening ports to well-known services|100|
|37|Follow the Route|Routing|Identifying the default gateway from a routing table|100|
|38|Name to Number|DNS|Tracing how a hostname resolves to an IP|125|

### 🔧 Troubleshooting 101
| # | Title | Category | Skill taught | Pts |
|---|-------|----------|--------------|-----|
|39|No Carrier|Physical Layer|Recognising a Layer 1 link failure|100|
|40|It Pings by IP but Not by Name|DNS|Isolating DNS failure from connectivity failure|125|
|41|Wrong Mask|Addressing|Spotting a subnet-mask misconfiguration|125|
|42|The Road Ends Here|Routing|Diagnosing a missing default route|150|
|43|Two Hosts, One Address|Addressing|Identifying an IP address conflict|125|
|44|Blocked at the Border|Firewall|Reading a traceroute that stalls at a filter|150|

---

## Networking 101 & Troubleshooting 101 (inline-data tracks)
Added as two separate tracks (slugs `networking`, `troubleshooting`). Unlike the
packet/log/email tracks, these carry **no artifacts**: the data a student needs
(`ip route`, `ss -tlnp`, a traceroute, a syslog line) is pasted into each challenge
`story` inside a `<code class='block-code'>` block — so there are no `generate.py`
files, no `/files/` downloads, and no routes for them. `.block-code` was given
`white-space: pre-wrap` so these multi-line dumps render; it was previously only
ever used for single-line snippets.

**Flags are computed/extracted values, never descriptive phrases, and every story
states an explicit `Flag format:` with placeholders** (e.g. `FLAG{bcast_a_b_c_d}`,
`FLAG{bad_prefix_NN}`). This is deliberate: a descriptive flag like
`FLAG{wrong_subnet_mask}` would either be unguessable or have to be printed on the
page (a giveaway). An extracted value (`FLAG{bad_prefix_16}`) is recoverable from
the evidence and proves the student actually diagnosed it. When adding challenges
here, keep that rule — the required value must appear in the inline evidence, and
the flag text must **not** appear in the story body (only the format placeholder).

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

### Learning Games tab (`/games`)
A nav tab sitting **between Documents and Instructor**. `/games` renders `GAMES_PAGE`
from the `LEARNING_GAMES` registry (a list of dicts: `slug`, `title`, `tagline`,
`blurb`, `file`, optional `run`); `/games/<slug>` serves that game's self-contained
HTML from the repo's `games/` directory (`GAMES_DIR`) via `send_from_directory`,
404ing on an unknown slug. **To add a game: drop its HTML in `games/` and append a
dict to `LEARNING_GAMES`** — no template or route change.

First game is **DOCKPUNCH** (`games/dockpunch.html`) — an interactive, searchable,
click-to-copy Docker/K8s/networking/security CLI cheat sheet. The source arrived
with a `fonts.googleapis.com` `@import`; it was **replaced with `@font-face` rules
pointing at the self-hosted `/static/fonts/JetBrainsMono-*.woff2`** so the page
honours the site's no-third-party-fonts policy (Space Grotesk falls back to the
system sans stack). Keep that when updating the file — don't reintroduce a remote
font. The card also shows the `docker build … && docker run` one-liner for the full
DOCKPUNCH container, which lives outside this repo.

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

### Planted source comment (`source_comment`)
A challenge with `"source_comment": True` (currently only #4, *View Source*) gets an
HTML comment emitted in `CHALLENGE_PAGE`'s `<head>`, just after `<title>`, carrying
that challenge's own `flag`. This is the only place a flag is deliberately served to
the browser. The key existed on challenge 4 for a while with **no code reading it**,
which made the challenge unsolvable — if you touch that template block, re-check
`/challenge/4` actually contains the comment. Worded as a developer TODO rather than
a bare `FLAG{}` so students practise spotting a realistic leak.

### Post-solve takeaway
`TAKEAWAYS[id]` is one line shown in the solved banner, plus a prominent
`.next-cta` to the next challenge (or back to the ladder on #20), and the Training
Notes auto-expand. Solving used to display only a point total.

### Writing a new club document
Quick-reference PDFs are authored as HTML in `docs_src/` and printed with headless
Chrome; `docs_src/README.md` has the exact command and the palette/type scale, which
were extracted from the original `What_is_a_CTF.pdf` so new documents match the house
style. Keep the source — restyle by editing CSS, don't re-author the PDF.

Filenames matter: `/docs` derives the displayed title from the filename, turning `_`
and `-` into spaces. `docs_src/` is deliberately **outside** `docs/`, so build sources
aren't served as documents.

### Per-challenge further reading
`DOC_LINKS[id]` lists PDF filenames from `docs/`. `_prepare_challenges()` resolves
them against `DOCS_DIR` at import and drops any that don't exist, so renaming a PDF
removes the link instead of producing a dead one.

### Tracks / modules
`MODULES` is the ordered track list (slug, name, icon, level, blurb); `MODULE_BY_SLUG`
indexes it. Every challenge carries `module`, and `_prepare_challenges()` defaults
anything missing one to `DEFAULT_MODULE` (`"foundations"`), so the original 20 needed
no edits. `module_progress()` builds the index's per-track counts/points/percent and
`module_neighbours()` gives prev/next **within a track** — challenge navigation no
longer assumes `id ± 1`.

Routes: `/` is the track picker (`INDEX_PAGE`), `/module/<slug>` is one track's grid
(`MODULE_PAGE`, which is the old index page). An unknown slug redirects to `/`.

**Adding a track:** append to `MODULES`, set `module` on the new challenges. The
category rows inside a track are derived from that track's challenges only.

### Challenge artifacts
`challenge_files/generate.py` builds every artifact at Docker build time, including
packet captures. `challenge_files/pcapgen.py` is a dependency-free pcap writer
(classic libpcap format, hand-built Ethernet/IPv4/TCP/UDP with correct checksums,
plus `TcpStream` for full handshake/data/teardown conversations and `dns_query`).
**No scapy in the image.** Captures were validated against tshark 4.6.9: HTTP, DNS,
and Telnet all dissect correctly and no checksum is flagged bad.

Two artifacts deliberately contain **no plaintext flag** — `dns_traffic.pcap`
(hex-encoded across subdomain labels) and `phish_04.eml` (base64 attachment) —
because decoding is the skill being taught. Don't "fix" them by embedding the flag.

`/files/<name>` serves these from `FILES_DIR`, resolved relative to `app.py`
(it was hardcoded to `/app/challenge_files`, which broke every download outside
Docker). The route **refuses any `.py`/`.pyc`** — `generate.py` and `pcapgen.py`
live in `FILES_DIR` and hard-code ~18 flags, so serving them handed out half the
answer key to anyone who guessed the URL. Keep that block if you touch the route;
don't allow-list by filename (a new build script would leak). Student artifacts
(.pcap/.eml/.log/.png/.pdf/.txt/.bin) are unaffected.

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
