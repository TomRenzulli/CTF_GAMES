# 🐻 BERA Cyber Training Academy — CTF

> *Twenty locked doors. Twenty flags. Zero excuses.*

Welcome, recruit. This is the training ground of the **BERA Cyber CTF Club**: a beginner-friendly Capture The Flag platform where you learn real hacking skills by actually breaking things (the things we built to be broken, that is).

No prior experience required. Curiosity mandatory. Snacks recommended.

```
   ____  _____ ____      _       ____ _____ _____
  | __ )| ____|  _ \    / \     / ___|_   _|  ___|
  |  _ \|  _| | |_) |  / _ \   | |     | | | |_
  | |_) | |___|  _ <  / ___ \  | |___  | | |  _|
  |____/|_____|_| \_\/_/   \_\  \____| |_| |_|
```

---

## 🎯 How to play

1. Open the platform in your browser.
2. Pick a challenge. Read the story. Squint suspiciously at everything.
3. Find the flag. It always looks like `FLAG{something_clever}`.
4. Submit it, collect points, feel like a movie hacker.
5. Stuck? Every challenge has **▶ Training Notes** that explain the concept, how to spot it, where it shows up in the real world, and the tools the pros use.

> ⚠️ Your score lives in your browser session. Clear your cookies and you start over. Consider it character building.

---

## 🪜 The Skill Ladder

Challenges get harder as you climb. Start at the bottom, end at the boss.

| # | Challenge | Category | Points |
|---|-----------|----------|-------:|
| 01 | Base64 Basics | 🔤 Encoding | 50 |
| 02 | Hex Signals | 🔤 Encoding | 50 |
| 03 | Binary Message | 🔤 Encoding | 50 |
| 04 | View Source | 🔭 Recon | 75 |
| 05 | HTTP Headers | 🔭 Recon | 75 |
| 06 | Strings Search | 📁 File Analysis | 100 |
| 07 | Wrong Extension | 📁 File Analysis | 100 |
| 08 | ROT13 | 🔐 Crypto | 100 |
| 09 | Caesar Brute Force | 🔐 Crypto | 125 |
| 10 | Cookie Monster | 🌐 Web | 125 |
| 11 | URL Parameters | 🌐 Web | 125 |
| 12 | robots.txt | 🔭 Recon | 150 |
| 13 | Directory Guessing | 🔭 Recon | 150 |
| 14 | Image Metadata | 🕵️ Forensics | 150 |
| 15 | Magic Bytes | 🕵️ Forensics | 150 |
| 16 | Default Credentials | 🔑 Auth | 175 |
| 17 | Weak Token | 🔑 Auth | 175 |
| 18 | Command Injection | 💉 Injection | 200 |
| 19 | SQL Injection | 💉 Injection | 200 |
| 20 | **Final Boss: Chain It** | ⛓️ Chain | 250 |

**Total: 2,575 points.** Get them all and earn eternal bragging rights (and possibly a sticker).

---

## 🧰 Recommended loadout

You can solve most of this with a browser and a terminal. Handy extras:

- **Browser DevTools** (`F12`): your new best friend
- **CyberChef**: the Swiss Army knife of decoding
- `curl`, `strings`, `file`, `xxd`, `exiftool`: classic command-line tools
- A notepad for writing down weird things you notice (they're never *just* weird)

---

## 📜 Rules of the range

- ✅ Hack the challenges. That's the whole point.
- ✅ Help your friends learn. Explaining a solve is the best way to master it.
- ❌ Don't post flags. Spoilers ruin the fun for everyone.
- ❌ Don't attack the server itself, other players, or anything outside the challenges.
- ❌ **Never use these techniques on systems you don't own or have written permission to test.** In the real world that's not a CTF, it's a crime.

---

## 🛠️ For instructors: running it yourself

You need Docker. That's it.

```bash
git clone https://github.com/TomRenzulli/CTF_GAMES.git
cd CTF_GAMES
docker compose up -d --build
```

Then open **http://localhost:9300** and start hacking.

> 🚨 **This app is intentionally vulnerable.** Challenge 18 is a real command injection. Run it in a lab, or put it behind nginx with a password or IP allowlist. Never expose it raw to the internet. Full deployment notes are in [`CLAUDE.md`](CLAUDE.md).

**Under the hood:** Python 3.11 · Flask · SQLite · Docker

---

## 🏴 Credits

Built by **Banshee** ([@TomRenzulli](https://github.com/TomRenzulli)) for the BERA Cyber CTF Club.

*Now go find some flags.* 🚩
