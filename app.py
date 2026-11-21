"""
Cyber Training Academy — 20-Flag Beginner Progression CTF
Single container, port 9300.
Each flag teaches exactly one concept before the next builds on it.
"""
from flask import (Flask, request, render_template_string,
                   redirect, url_for, session, send_from_directory,
                   Response)
import secrets, base64, sqlite3, os, subprocess, hashlib, threading

app = Flask(__name__)


def _load_secret_key():
    """Stable signing key so student progress survives a restart or redeploy.

    A key generated per process would invalidate every session cookie on each
    `docker compose up --build`, wiping everyone's solves mid-meeting, and would
    break outright under multiple workers (each worker signing with its own key).
    Priority: CTF_SECRET_KEY env var -> key file -> freshly generated key file.
    """
    env_key = os.environ.get("CTF_SECRET_KEY", "").strip()
    if env_key:
        return env_key

    key_path = os.environ.get("CTF_SECRET_KEY_FILE", "/data/secret_key")
    try:
        with open(key_path, "r", encoding="utf-8") as fh:
            stored = fh.read().strip()
        if stored:
            return stored
    except OSError:
        pass

    generated = secrets.token_hex(32)
    try:
        # 0o600: readable only by the app user.
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(generated)
    except OSError:
        # Read-only filesystem: fall back to an in-process key. Sessions still
        # work for the life of the container; set CTF_SECRET_KEY to persist.
        print("WARNING: could not persist session key to "
              f"{key_path}; set CTF_SECRET_KEY to keep progress across restarts.")
    return generated


app.secret_key = _load_secret_key()

# ── Challenge registry ────────────────────────────────────────────────────────
CHALLENGES = [
    # 1-3: Encoding
    {
        "id": 1, "title": "01 · Base64 Basics",
        "category": "Encoding",
        "skill": "Decoding Base64",
        "story": "An analyst found this string in a config file: <code>RkxBR3tiYXNlNjRfaXNfbm90X2VuY3J5cHRpb259</code><br><br>"
                 "It's Base64-encoded. Decode it to find the flag.<br><br>"
                 "<b>Hint:</b> In your terminal: <code>echo 'RkxBR3tiYXNlNjRfaXNfbm90X2VuY3J5cHRpb259' | base64 -d</code>",
        "flag": "FLAG{base64_is_not_encryption}",
        "points": 50,
        "notes": [
            ("What is Base64?", "Base64 is an encoding scheme that converts binary data into a string of 64 printable ASCII characters (A–Z, a–z, 0–9, +, /). It's used to safely transmit binary data over text-based channels like email or JSON APIs. It is <b>not</b> encryption — anyone can decode it instantly."),
            ("How to spot it", "Base64 strings typically end with one or two <code>=</code> padding characters and only use letters, numbers, <code>+</code>, and <code>/</code>. Length is always a multiple of 4."),
            ("Real-world use", "You'll find Base64 everywhere: JWT tokens, email attachments (MIME), embedded images in HTML (<code>data:image/png;base64,...</code>), and API credentials. Attackers also use it to obfuscate payloads in phishing documents."),
            ("Key tools", "<code>base64 -d</code> (Linux/Mac) &nbsp;·&nbsp; <code>certutil -decode</code> (Windows) &nbsp;·&nbsp; <a href='https://gchq.github.io/CyberChef/' target='_blank'>CyberChef</a> → 'From Base64' &nbsp;·&nbsp; Python: <code>import base64; base64.b64decode(s)</code>"),
        ],
    },
    {
        "id": 2, "title": "02 · Hex Signals",
        "category": "Encoding",
        "skill": "Decoding hexadecimal",
        "story": "Download the intercepted signal file and decode the hex string inside it.<br><br>"
                 "<a href='/files/signal.txt' class='btn-link'>⬇ Download signal.txt</a><br><br>"
                 "<b>Hint:</b> <code>echo '46 4c 41 47...' | xxd -r -p</code> &nbsp;or use CyberChef → 'From Hex'",
        "flag": "FLAG{hex_decoded_you_found_me}",
        "points": 50,
        "notes": [
            ("What is Hex encoding?", "Hexadecimal (base-16) uses digits 0–9 and letters A–F to represent each byte as exactly two characters. Every character you type has an ASCII code, and that code can be written in hex. 'A' = 0x41, 'F' = 0x46, 'L' = 0x4C, etc."),
            ("Why do analysts see hex?", "Network packet captures, memory dumps, file headers, and disassembled shellcode all appear in hex. Recognising hex-encoded data on sight is a core analyst skill."),
            ("Common hex signatures", "<code>FF D8 FF</code> = JPEG &nbsp;·&nbsp; <code>89 50 4E 47</code> = PNG &nbsp;·&nbsp; <code>4D 5A</code> = Windows EXE &nbsp;·&nbsp; <code>25 50 44 46</code> = PDF. These are called <em>magic bytes</em>."),
            ("Key tools", "<code>xxd</code>, <code>xxd -r -p</code> to reverse &nbsp;·&nbsp; <code>python3 -c \"print(bytes.fromhex('...')\"</code> &nbsp;·&nbsp; CyberChef → 'From Hex'"),
        ],
    },
    {
        "id": 3, "title": "03 · Binary Message",
        "category": "Encoding",
        "skill": "Reading binary / ASCII",
        "story": "Download the binary transmission and convert each 8-bit group to its ASCII character.<br><br>"
                 "<a href='/files/binary_message.txt' class='btn-link'>⬇ Download binary_message.txt</a><br><br>"
                 "<b>Hint:</b> Use CyberChef → 'From Binary', or Python: <code>int('01000110', 2)</code> → <code>chr()</code>",
        "flag": "FLAG{bits_and_bytes_101}",
        "points": 50,
        "notes": [
            ("Bits and bytes", "A <em>bit</em> is a single 0 or 1. A <em>byte</em> is 8 bits. Modern computers store everything as bytes. The ASCII standard maps each printable character to a number 0–127, which fits in 7 bits (we use 8 with a leading zero)."),
            ("ASCII quick reference", "'A' = 65 = 01000001 &nbsp;·&nbsp; 'Z' = 90 = 01011010 &nbsp;·&nbsp; 'a' = 97 = 01100001 &nbsp;·&nbsp; '0' (digit) = 48 = 00110000. Notice uppercase letters differ from lowercase by exactly one bit (bit 5)."),
            ("Why this matters", "When you analyse malware, network traffic, or embedded firmware you often work with raw bytes. Being comfortable converting between binary, hex, decimal, and ASCII is foundational."),
            ("Key tools", "CyberChef → 'From Binary' &nbsp;·&nbsp; Python: <code>chr(int('01000001', 2))</code> &nbsp;·&nbsp; <code>man ascii</code> in your terminal shows the full table"),
        ],
    },
    # 4-5: Recon
    {
        "id": 4, "title": "04 · View Source",
        "category": "Recon",
        "skill": "Reading HTML page source",
        "story": "Developers sometimes leave things in the source code they shouldn't.<br><br>"
                 "Right-click this page and choose <b>View Page Source</b> (or press <kbd>Ctrl+U</kbd> / <kbd>Cmd+U</kbd>).<br>"
                 "Search for the flag hidden in an HTML comment.<br><br>"
                 "<b>Hint:</b> HTML comments look like <code>&lt;!-- this is a comment --&gt;</code>",
        "flag": "FLAG{source_code_tells_all}",
        "points": 75,
        "source_comment": True,
        "notes": [
            ("What is page source?", "Every webpage your browser renders is built from HTML sent by the server. The browser interprets and displays it, but the raw text is always there — right-click → View Page Source (or Ctrl+U). Comments, hidden form fields, API keys, and internal paths are commonly found here."),
            ("What to look for", "HTML comments (<code>&lt;!-- --&gt;</code>), hidden inputs (<code>&lt;input type='hidden'&gt;</code>), commented-out code blocks, hardcoded credentials, and internal paths or filenames referenced in scripts."),
            ("Real-world finding", "Bug bounty hunters routinely find API keys, internal endpoint URLs, staging credentials, and developer notes in page source. In 2021, a researcher found AWS keys in a Fortune 500 company's public JS bundle."),
            ("Key tools", "<kbd>Ctrl+U</kbd> / <kbd>Cmd+U</kbd> for full source &nbsp;·&nbsp; Browser DevTools (F12) → Elements for the live DOM &nbsp;·&nbsp; <kbd>Ctrl+F</kbd> to search source for keywords like 'key', 'pass', 'secret', 'TODO', 'FLAG'"),
        ],
    },
    {
        "id": 5, "title": "05 · HTTP Headers",
        "category": "Recon",
        "skill": "Inspecting HTTP response headers",
        "story": "Servers sometimes leak information in HTTP response headers that aren't visible on the page.<br><br>"
                 "Send a request to <code>/header-challenge</code> and inspect the response headers.<br><br>"
                 "<b>Hint:</b> <code>curl -I http://localhost:9300/header-challenge</code> &nbsp;or use browser DevTools → Network tab → click the request → Headers",
        "flag": "FLAG{http_headers_talk_too_much}",
        "points": 75,
        "notes": [
            ("What are HTTP headers?", "HTTP headers are metadata sent alongside every web request and response. They control caching, authentication, content type, security policies, and more. They're invisible to regular users but readable with any developer tool."),
            ("Headers that leak info", "<code>Server: Apache/2.4.1</code> reveals software versions &nbsp;·&nbsp; <code>X-Powered-By: PHP/7.2</code> reveals language/version &nbsp;·&nbsp; <code>X-Debug-Token</code> reveals debug info &nbsp;·&nbsp; Custom headers like <code>X-Internal-Path</code> sometimes appear in misconfigured apps."),
            ("Security headers to know", "<code>Content-Security-Policy</code>, <code>X-Frame-Options</code>, <code>Strict-Transport-Security</code>, and <code>X-Content-Type-Options</code> are headers that <em>defend</em> against attacks. Their absence is itself a finding on a pentest."),
            ("Key tools", "<code>curl -I &lt;url&gt;</code> for headers only &nbsp;·&nbsp; <code>curl -v</code> for full request+response &nbsp;·&nbsp; Browser DevTools → Network → click any request → Headers tab &nbsp;·&nbsp; Burp Suite intercept proxy"),
        ],
    },
    # 6-7: File Analysis
    {
        "id": 6, "title": "06 · Strings Search",
        "category": "File Analysis",
        "skill": "Using the `strings` command",
        "story": "Binary files can contain readable text hidden among the garbage bytes.<br><br>"
                 "<a href='/files/mystery.bin' class='btn-link'>⬇ Download mystery.bin</a><br><br>"
                 "Run <code>strings mystery.bin</code> and look for the flag among the output.<br><br>"
                 "<b>Hint:</b> <code>strings mystery.bin | grep FLAG</code>",
        "flag": "FLAG{strings_reveals_all_secrets}",
        "points": 100,
        "notes": [
            ("What does `strings` do?", "The <code>strings</code> command scans any file — binary or text — and extracts sequences of printable ASCII characters that are at least 4 characters long (configurable with <code>-n</code>). Malware analysts use it as a first-pass triage tool on every suspicious file."),
            ("What you find with strings", "Malware often contains hardcoded C2 server URLs, registry keys it will modify, error messages, debug strings, and sometimes credentials — all readable with <code>strings</code>. It's always the first command run on an unknown binary."),
            ("Limitations", "Sophisticated malware obfuscates its strings (XOR encoding, base64, etc.) to defeat <code>strings</code> analysis. When strings comes up empty, the next step is dynamic analysis or disassembly."),
            ("Key tools", "<code>strings &lt;file&gt;</code> &nbsp;·&nbsp; <code>strings -n 8 &lt;file&gt;</code> (longer minimum) &nbsp;·&nbsp; <code>strings &lt;file&gt; | grep -i password</code> &nbsp;·&nbsp; <code>floss</code> (FireEye's deobfuscating strings tool)"),
        ],
    },
    {
        "id": 7, "title": "07 · Wrong Extension",
        "category": "File Analysis",
        "skill": "Using the `file` command / magic bytes",
        "story": "Not every file is what its extension says it is.<br><br>"
                 "<a href='/files/definitely_a_text_file.txt' class='btn-link'>⬇ Download definitely_a_text_file.txt</a><br><br>"
                 "Run <code>file definitely_a_text_file.txt</code> to see what it really is, then open it with the right tool.<br><br>"
                 "<b>Hint:</b> If <code>file</code> says it's a ZIP, try: <code>unzip definitely_a_text_file.txt</code>",
        "flag": "FLAG{file_command_knows_all}",
        "points": 100,
        "notes": [
            ("What are magic bytes?", "Every file format has a signature — a specific sequence of bytes at the start of the file that identifies its true type. The OS extension is just a label; the <code>file</code> command reads the actual bytes. A renamed .exe is still an executable."),
            ("Common magic bytes", "<code>FF D8 FF</code> = JPEG &nbsp;·&nbsp; <code>89 50 4E 47</code> = PNG &nbsp;·&nbsp; <code>50 4B 03 04</code> = ZIP (also .docx/.xlsx — Office files are ZIPs!) &nbsp;·&nbsp; <code>4D 5A</code> = Windows PE executable &nbsp;·&nbsp; <code>7F 45 4C 46</code> = Linux ELF executable"),
            ("Why attackers do this", "Malware is often disguised as a .pdf, .jpg, or .txt to bypass filters and trick users. A phishing attachment named 'invoice.pdf' might actually be a .exe renamed with a .pdf extension. The <code>file</code> command sees through this."),
            ("Key tools", "<code>file &lt;filename&gt;</code> &nbsp;·&nbsp; <code>xxd &lt;file&gt; | head -2</code> to see raw bytes &nbsp;·&nbsp; <a href='https://en.wikipedia.org/wiki/List_of_file_signatures' target='_blank'>File Signatures Wiki</a> &nbsp;·&nbsp; <code>binwalk</code> to find embedded files"),
        ],
    },
    # 8-9: Crypto
    {
        "id": 8, "title": "08 · ROT13",
        "category": "Crypto",
        "skill": "ROT13 / Caesar cipher",
        "story": "A classic. This message was 'encrypted' with ROT13:<br><br>"
                 "<code class='block-code'>SYNT{ebg13_vf_whfg_n_cneebg}</code><br><br>"
                 "Rotate each letter 13 positions back to read the flag.<br><br>"
                 "<b>Hint:</b> <code>echo 'SYNT{ebg13_vf_whfg_n_cneebg}' | tr 'A-Za-z' 'N-ZA-Mn-za-m'</code>",
        "flag": "FLAG{rot13_is_just_a_parrot}",
        "points": 100,
        "notes": [
            ("What is ROT13?", "ROT13 ('rotate by 13') shifts every letter 13 places in the alphabet. A→N, B→O, ..., N→A. Because the alphabet has 26 letters, applying ROT13 twice returns the original — it's its own inverse. It's also a special case of the Caesar cipher."),
            ("Is it real encryption?", "No. ROT13 provides zero confidentiality. It was originally used on Usenet to hide spoilers and offensive jokes — just enough friction to require intent to read. Anyone can decode it instantly. Never use it for security."),
            ("Caesar cipher history", "Julius Caesar reportedly used a shift-by-3 cipher for military communications. ROT13 is shift-by-13. Modern cryptography replaced all substitution ciphers because they're trivially broken by frequency analysis."),
            ("Key tools", "<code>tr 'A-Za-z' 'N-ZA-Mn-za-m'</code> &nbsp;·&nbsp; <code>python3 -c \"import codecs; print(codecs.decode('SYNT{...}', 'rot13'))\"</code> &nbsp;·&nbsp; CyberChef → 'ROT13'"),
        ],
    },
    {
        "id": 9, "title": "09 · Caesar Brute Force",
        "category": "Crypto",
        "skill": "Brute-forcing Caesar cipher (26 shifts)",
        "story": "This message was shifted by an unknown amount. Try all 26 possibilities:<br><br>"
                 "<code class='block-code'>IRGQ{lhk_jxhzr_kyv_jyzwk}</code><br><br>"
                 "One of the 26 rotations will produce a readable <code>FLAG{...}</code>.<br><br>"
                 "<b>Hint:</b> CyberChef → 'ROT13 Brute Force', or write a loop in Python:<br>"
                 "<code>for i in range(26): print(i, ''.join(chr((ord(c)-65-i)%26+65) if c.isupper() else c for c in msg))</code>",
        "flag": "FLAG{you_brute_the_shift}",
        "points": 125,
        "notes": [
            ("What is brute force?", "Brute force means trying every possible value until one works. For a Caesar cipher, there are only 26 possible keys (shifts 0–25) — so you can check all of them in under a second. Brute force is only practical when the keyspace is small."),
            ("Frequency analysis", "Even without brute force, Caesar ciphers can be broken by frequency analysis: 'E' is the most common letter in English (~13%), so whichever ciphertext letter appears most often was probably 'E'. Shift by that difference and you have the key."),
            ("When brute force doesn't work", "Modern encryption (AES-256) has 2^256 possible keys — more than atoms in the observable universe. Trying all of them would take longer than the age of the universe even with all computers ever built. Good encryption is brute-force-proof."),
            ("Key tools", "CyberChef → 'ROT13 Brute Force' &nbsp;·&nbsp; <a href='https://www.dcode.fr/caesar-cipher' target='_blank'>dcode.fr Caesar solver</a> &nbsp;·&nbsp; Python loop with <code>chr((ord(c) - shift - 65) % 26 + 65)</code>"),
        ],
    },
    # 10-11: Web Basics
    {
        "id": 10, "title": "10 · Cookie Monster",
        "category": "Web",
        "skill": "Reading and editing browser cookies",
        "story": "This app trusts a cookie to decide who you are.<br><br>"
                 "Visit <a href='/cookie-challenge' class='btn-link'>/cookie-challenge</a> — you'll be told you're a 'guest'.<br><br>"
                 "Open DevTools → Application → Cookies. Change the <code>role</code> cookie value to <code>admin</code>, then refresh.<br><br>"
                 "<b>Hint:</b> Never trust client-side values. The server should always re-verify identity.",
        "flag": "FLAG{cookies_are_not_auth}",
        "points": 125,
        "notes": [
            ("What are cookies?", "Cookies are small key=value strings that the server sends to your browser and the browser automatically includes in every subsequent request. They're used for session management, preferences, and tracking. They live in your browser and <em>you</em> can edit them."),
            ("The trust problem", "Any value stored on the client side — cookies, localStorage, hidden form fields, URL parameters — can be modified by the user. Trusting <code>role=admin</code> in a cookie without server-side verification is a critical auth flaw."),
            ("Secure cookie practices", "Production apps should use signed/encrypted session tokens (not readable plaintext), set <code>HttpOnly</code> (no JS access), <code>Secure</code> (HTTPS only), and <code>SameSite=Strict</code> flags. The role check happens on the server using a DB lookup, never the cookie value."),
            ("Key tools", "Browser DevTools → Application tab → Cookies &nbsp;·&nbsp; <code>document.cookie</code> in the console &nbsp;·&nbsp; Burp Suite to intercept and modify mid-flight &nbsp;·&nbsp; <code>curl --cookie 'role=admin'</code>"),
        ],
    },
    {
        "id": 11, "title": "11 · URL Parameters",
        "category": "Web",
        "skill": "Manipulating URL query parameters",
        "story": "Some apps pass sensitive data in the URL itself.<br><br>"
                 "Visit <a href='/param-challenge?user=guest' class='btn-link'>/param-challenge?user=guest</a><br><br>"
                 "Modify the URL parameter to access the admin area and grab the flag.<br><br>"
                 "<b>Hint:</b> Change <code>?user=guest</code> to <code>?user=admin</code> in the address bar.",
        "flag": "FLAG{url_params_are_not_access_control}",
        "points": 125,
        "notes": [
            ("What are URL parameters?", "The query string is the part of a URL after <code>?</code>. It's a list of <code>key=value</code> pairs separated by <code>&amp;</code>. Example: <code>/search?q=hello&amp;page=2</code>. Both the server and the user can see and modify these values."),
            ("Why this is a vulnerability", "Using a URL parameter for access control (<code>?admin=true</code>, <code>?role=user</code>, <code>?userid=1337</code>) is called an Insecure Direct Object Reference (IDOR) or broken access control — one of the OWASP Top 10 most critical web vulnerabilities."),
            ("Real-world examples", "IDOR bugs have exposed millions of records. In 2020, a researcher found that changing a numeric ID in a URL parameter exposed any user's private data on a major platform. These bugs earn significant bug bounty payouts."),
            ("Key tools", "Just the address bar &nbsp;·&nbsp; Burp Suite Repeater for systematic testing &nbsp;·&nbsp; <code>curl 'http://site/page?user=admin'</code> &nbsp;·&nbsp; Browser DevTools → Network to see all parameters being sent"),
        ],
    },
    # 12-13: Logic / Hidden Paths
    {
        "id": 12, "title": "12 · robots.txt",
        "category": "Recon",
        "skill": "Checking robots.txt for hidden paths",
        "story": "Webmasters use <code>robots.txt</code> to tell search engines which pages NOT to index.<br>"
                 "Ironically this is often a roadmap to sensitive areas.<br><br>"
                 "Check <a href='/robots.txt' class='btn-link'>/robots.txt</a> and visit the disallowed path.<br><br>"
                 "<b>Hint:</b> <code>curl http://localhost:9300/robots.txt</code>",
        "flag": "FLAG{robots_txt_is_not_a_lock}",
        "points": 150,
        "notes": [
            ("What is robots.txt?", "robots.txt is a plain text file at the root of a website (<code>/robots.txt</code>) that tells search engine crawlers which pages they should <em>not</em> index. It's a convention, not a security control — any browser or script can still access disallowed paths."),
            ("Why it leaks info", "Webmasters use <code>Disallow:</code> entries to hide admin panels, staging environments, internal tools, and backup files from search results. This creates a public roadmap of sensitive paths. Every penetration tester checks robots.txt first."),
            ("It's not security", "robots.txt is a request, not enforcement. Adding <code>Disallow: /admin</code> does not prevent anyone from visiting <code>/admin</code> — it only asks Google not to index it. Actual access control requires authentication on the server."),
            ("Key tools", "<code>curl https://target.com/robots.txt</code> &nbsp;·&nbsp; Check it manually during every web recon &nbsp;·&nbsp; Recon tools like <code>amass</code>, <code>subfinder</code>, and Burp Suite's spider check it automatically"),
        ],
    },
    {
        "id": 13, "title": "13 · Directory Guessing",
        "category": "Recon",
        "skill": "Discovering hidden endpoints by guessing",
        "story": "Not all pages are linked from the navigation. Common paths like <code>/admin</code>, "
                 "<code>/backup</code>, <code>/secret</code>, <code>/flag</code> are often forgotten.<br><br>"
                 "Poke around this app — one of these common paths has a flag waiting:<br>"
                 "<code>/admin</code> &nbsp; <code>/backup</code> &nbsp; <code>/secret</code> &nbsp; <code>/dev</code><br><br>"
                 "<b>Hint:</b> Tools like <code>gobuster</code> or <code>ffuf</code> automate this. For now, just try them manually.",
        "flag": "FLAG{hidden_paths_hide_in_plain_sight}",
        "points": 150,
        "notes": [
            ("What is directory busting?", "Web servers often have pages and files that aren't linked anywhere in the UI but are still accessible if you know the path. Directory busting (or content discovery) uses wordlists of common names to find them automatically."),
            ("Common paths to always try", "<code>/admin</code>, <code>/administrator</code>, <code>/backup</code>, <code>/config</code>, <code>/debug</code>, <code>/dev</code>, <code>/.env</code>, <code>/api</code>, <code>/test</code>, <code>/old</code>, <code>/staging</code>, <code>/.git</code>. Exposed <code>.git</code> repos are an especially high-severity finding."),
            ("Wordlists", "The SecLists repository contains wordlists with thousands of common path names gathered from real applications. <code>gobuster</code> and <code>ffuf</code> use these to send hundreds of requests per second and report which paths return 200 OK instead of 404."),
            ("Key tools", "<code>gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt</code> &nbsp;·&nbsp; <code>ffuf -u http://target/FUZZ -w wordlist.txt</code> &nbsp;·&nbsp; <code>dirsearch</code> &nbsp;·&nbsp; Burp Suite → Engagement Tools → Discover Content"),
        ],
    },
    # 14-15: File Formats
    {
        "id": 14, "title": "14 · Image Metadata",
        "category": "Forensics",
        "skill": "Extracting EXIF / metadata from images",
        "story": "Images carry hidden metadata — camera model, GPS coordinates, author, and sometimes flags.<br><br>"
                 "<a href='/files/training_badge.png' class='btn-link'>⬇ Download training_badge.png</a><br><br>"
                 "Inspect its metadata to find the flag.<br><br>"
                 "<b>Hint:</b> <code>exiftool training_badge.png</code> or use CyberChef → Extract EXIF, "
                 "or: <code>strings training_badge.png | grep FLAG</code>",
        "flag": "FLAG{metadata_hides_in_plain_sight}",
        "points": 150,
        "notes": [
            ("What is image metadata?", "Digital images contain far more than pixels. EXIF (Exchangeable Image File Format) metadata is embedded in JPEG and PNG files and stores: camera make/model, lens, shutter speed, GPS coordinates, timestamp, software used, and custom text fields."),
            ("Privacy and OPSEC implications", "Every photo taken on a smartphone includes GPS coordinates unless you've disabled geotagging. Journalists, activists, and whistleblowers have been located by GPS data in photos they posted publicly. John McAfee was found in Belize this way in 2012."),
            ("PNG tEXt chunks", "PNG files use a chunk-based format. The <code>tEXt</code> chunk stores arbitrary key-value text pairs. Forensics challenges often hide flags in these chunks. <code>strings</code> will reveal them because they're plain ASCII."),
            ("Key tools", "<code>exiftool &lt;file&gt;</code> — the gold standard for metadata extraction &nbsp;·&nbsp; <code>strings &lt;image&gt;</code> for quick triage &nbsp;·&nbsp; CyberChef → 'Extract EXIF' &nbsp;·&nbsp; <code>identify -verbose &lt;image&gt;</code> (ImageMagick)"),
        ],
    },
    {
        "id": 15, "title": "15 · Magic Bytes",
        "category": "Forensics",
        "skill": "Identifying files by magic bytes / file header",
        "story": "The file extension lies. This 'PDF' is actually something else.<br><br>"
                 "<a href='/files/report.pdf' class='btn-link'>⬇ Download report.pdf</a><br><br>"
                 "Check the first bytes to identify the real format, open it correctly, and find the flag embedded as a comment.<br><br>"
                 "<b>Hint:</b> <code>xxd report.pdf | head</code> — JPEG files start with <code>FF D8 FF</code>. "
                 "JPEG comment markers are <code>FF FE</code>.",
        "flag": "FLAG{magic_bytes_dont_lie}",
        "points": 150,
        "notes": [
            ("File signatures", "Every binary file format starts with a unique sequence of bytes called its 'magic number' or file signature. The <code>file</code> command and forensic tools use these to identify true file types regardless of extension."),
            ("JPEG structure", "A JPEG starts with <code>FF D8 FF</code> and ends with <code>FF D9</code>. Between those markers, it contains segments identified by two-byte markers. The Comment segment (<code>FF FE</code>) stores arbitrary text — often used to embed metadata or, in CTF challenges, flags."),
            ("Forensic significance", "Attackers rename malware to benign extensions. Forensic investigators always verify file type by magic bytes, never extension. Tools like Autopsy, Sleuth Kit, and FTK automatically identify files by signature during disk analysis."),
            ("Key tools", "<code>file &lt;filename&gt;</code> &nbsp;·&nbsp; <code>xxd &lt;file&gt; | head</code> to inspect hex &nbsp;·&nbsp; <a href='https://en.wikipedia.org/wiki/List_of_file_signatures' target='_blank'>File Signatures reference</a> &nbsp;·&nbsp; <code>binwalk &lt;file&gt;</code> to carve embedded files"),
        ],
    },
    # 16-17: Auth
    {
        "id": 16, "title": "16 · Default Credentials",
        "category": "Auth",
        "skill": "Testing default / common credentials",
        "story": "Many systems ship with default credentials that are never changed.<br><br>"
                 "Try to log in at <a href='/default-login' class='btn-link'>/default-login</a> using common defaults.<br><br>"
                 "<b>Hint:</b> Try combinations like <code>admin/admin</code>, <code>admin/password</code>, "
                 "<code>root/root</code>, <code>admin/1234</code>",
        "flag": "FLAG{change_your_default_creds}",
        "points": 175,
        "notes": [
            ("The default credential problem", "Vendors ship network equipment, IoT devices, software platforms, and cloud services with factory-set credentials like <code>admin/admin</code> or <code>admin/password</code>. Many are never changed. This is one of the most common causes of breaches."),
            ("How widespread is this?", "The Mirai botnet (2016) — which caused major internet outages — recruited 600,000 IoT devices using only 61 default credential pairs. Shodan.io scans the internet and indexes devices still using defaults. You can find cameras, routers, and PLCs today."),
            ("CISA guidance", "CISA's Known Exploited Vulnerabilities catalog includes default credential issues. The White House National Cybersecurity Strategy explicitly calls out default passwords as a systemic risk. Many countries now ban them by law for consumer IoT devices."),
            ("Key tools", "<a href='https://www.defaultpassword.com/' target='_blank'>defaultpassword.com</a> &nbsp;·&nbsp; <a href='https://cirt.net/passwords' target='_blank'>cirt.net/passwords</a> &nbsp;·&nbsp; <code>hydra</code> for automated testing (only on systems you own) &nbsp;·&nbsp; Shodan for finding exposed devices"),
        ],
    },
    {
        "id": 17, "title": "17 · Weak Token",
        "category": "Auth",
        "skill": "Predicting / forging weak session tokens",
        "story": "This app generates 'secure' tokens based on the username and a predictable algorithm.<br><br>"
                 "Visit <a href='/token-challenge' class='btn-link'>/token-challenge</a> to get a guest token, "
                 "then figure out the pattern and forge an admin token.<br><br>"
                 "<b>Hint:</b> Look at your token carefully. It might just be <code>base64(username)</code>. "
                 "What would <code>base64('admin')</code> look like?",
        "flag": "FLAG{weak_tokens_are_predictable}",
        "points": 175,
        "notes": [
            ("What makes a token 'weak'?", "A session token is meant to be an unpredictable secret that proves who you are. A token is weak when it's derived from predictable data: username, user ID, timestamp, sequential number, or a simple encoding like Base64. An attacker who sees one token can predict or forge others."),
            ("JWT vulnerabilities", "JSON Web Tokens (JWTs) are the modern version of this challenge. JWTs use the format <code>header.payload.signature</code> all Base64-encoded. Misconfigurations include: accepting <code>alg:none</code> (no signature), using weak secrets crackable by hashcat, or trusting the <code>alg</code> field the user controls."),
            ("Secure token generation", "Proper session tokens are cryptographically random (use <code>secrets.token_hex(32)</code> in Python, never <code>random</code>), stored server-side in a session store, short-lived, and invalidated on logout. The token is a lookup key, not a data carrier."),
            ("Key tools", "<code>echo -n 'admin' | base64</code> &nbsp;·&nbsp; <a href='https://jwt.io' target='_blank'>jwt.io</a> to decode JWTs &nbsp;·&nbsp; <code>hashcat</code> to crack weak JWT secrets &nbsp;·&nbsp; Burp Suite JWT Scanner extension"),
        ],
    },
    # 18-19: Injection intro
    {
        "id": 18, "title": "18 · Command Injection",
        "category": "Injection",
        "skill": "Basic OS command injection via shell metacharacters",
        "story": "This ping tool passes user input directly to the shell.<br><br>"
                 "Visit <a href='/ping-tool' class='btn-link'>/ping-tool</a> and enter a hostname to ping.<br><br>"
                 "Instead of a hostname, try injecting an extra command using <code>;</code> or <code>&amp;&amp;</code>.<br><br>"
                 "<b>Hint:</b> Try: <code>127.0.0.1; cat /flag18.txt</code>",
        "flag": "FLAG{shell_metacharacters_execute_commands}",
        "points": 200,
        "notes": [
            ("What is command injection?", "Command injection occurs when user input is passed unsanitised to a system shell. The attacker uses shell metacharacters (<code>;</code>, <code>&amp;&amp;</code>, <code>|</code>, <code>`</code>, <code>$()</code>) to chain or inject additional OS commands that the server executes."),
            ("Shell metacharacters cheat sheet", "<code>;</code> — run next command regardless &nbsp;·&nbsp; <code>&amp;&amp;</code> — run next command if first succeeds &nbsp;·&nbsp; <code>||</code> — run next if first fails &nbsp;·&nbsp; <code>|</code> — pipe output &nbsp;·&nbsp; <code>`cmd`</code> or <code>$(cmd)</code> — command substitution"),
            ("Real-world severity", "Command injection is consistently in the OWASP Top 10 and rated Critical. A successful injection gives the attacker OS-level code execution as the web server user, enabling full system compromise, data exfiltration, and lateral movement. Never pass user input to shell functions."),
            ("Prevention", "Use language-native functions instead of shell (<code>socket.getaddrinfo()</code> instead of <code>ping</code>). If shell is required, use parameterised subprocess calls (<code>subprocess.run(['ping', '-c', '1', host])</code> — pass a list, not a string), and whitelist valid input characters."),
        ],
    },
    {
        "id": 19, "title": "19 · SQL Injection",
        "category": "Injection",
        "skill": "Classic SQL injection (OR 1=1)",
        "story": "This login form builds a SQL query using your input without sanitising it.<br><br>"
                 "Visit <a href='/sqli-login' class='btn-link'>/sqli-login</a> and bypass the password check.<br><br>"
                 "<b>Hint:</b> Username: <code>admin'--</code> &nbsp; or &nbsp; Username: <code>' OR '1'='1</code>",
        "flag": "FLAG{sql_injection_bypasses_auth}",
        "points": 200,
        "notes": [
            ("What is SQL injection?", "SQL injection (SQLi) occurs when user input is embedded directly into a SQL query. An attacker who inputs <code>'</code> (a single quote) can break out of the string context and inject arbitrary SQL. This can bypass authentication, dump entire databases, or modify/delete data."),
            ("How the bypass works", "The vulnerable query looks like: <code>SELECT * FROM users WHERE username='[input]' AND password='[input]'</code>. If you enter <code>admin'--</code> as username, the query becomes: <code>...WHERE username='admin'--' AND password='...'</code>. The <code>--</code> comments out the password check."),
            ("Impact", "SQLi has caused some of the biggest breaches in history: Heartland Payment Systems (134M cards), Sony Pictures, TalkTalk, and countless others. It's ranked #3 in OWASP Top 10. A single SQLi vulnerability can expose an entire database."),
            ("Prevention", "Always use parameterised queries / prepared statements: <code>cursor.execute('SELECT * FROM users WHERE username=?', (username,))</code>. The DB driver handles escaping automatically. ORMs like SQLAlchemy also protect you by default. Never concatenate user input into SQL strings."),
        ],
    },
    # 20: Final boss
    {
        "id": 20, "title": "20 · Final Boss: Chain It",
        "category": "Chain",
        "skill": "Multi-step: recon → decode → submit",
        "story": "The final challenge combines what you've learned.<br><br>"
                 "<b>Step 1:</b> Check <a href='/final/robots.txt' class='btn-link'>/final/robots.txt</a> for a hidden path.<br>"
                 "<b>Step 2:</b> Visit that path — you'll get a Base64-encoded clue.<br>"
                 "<b>Step 3:</b> Decode it to get the real flag endpoint.<br>"
                 "<b>Step 4:</b> Visit that endpoint with the correct <code>?key=</code> parameter.<br><br>"
                 "<b>Hint:</b> Each step is something you've already done — robots.txt, Base64, URL params.",
        "flag": "FLAG{chain_all_the_skills_together}",
        "points": 250,
        "notes": [
            ("Why chaining matters", "Real attacks are never a single trick. An adversary chains: OSINT → credential stuffing → session hijack → privilege escalation → data exfil. Defenders think in kill chains too (Lockheed Martin Cyber Kill Chain, MITRE ATT&CK). This challenge simulates that multi-step mindset."),
            ("The recon-to-exploit pipeline", "Every engagement follows the same flow: (1) Enumerate what exists, (2) Identify what's exposed, (3) Understand the mechanism, (4) Craft your input, (5) Escalate. The specific techniques change but the pipeline stays the same whether you're doing CTF, bug bounty, or a red team engagement."),
            ("Building your methodology", "As you do more CTFs and real-world assessments, you'll develop a personal methodology — a checklist of things you always try first. Robots.txt, source view, headers, cookies, and params are all standard first-pass checks before touching any web target."),
            ("Where to go next", "You've completed the Cyber Training Academy foundation track. Next steps: <a href='https://tryhackme.com' target='_blank'>TryHackMe</a> (guided rooms), <a href='https://hackthebox.com' target='_blank'>Hack The Box</a> (harder machines), <a href='https://portswigger.net/web-security' target='_blank'>PortSwigger Web Academy</a> (free, in-depth web), and the club's advanced CTF tiers."),
        ],
    },
]


# ── Modules 2-5: Network, Logs, Phishing, OT ─────────────────────────────────
# Each challenge works on a real artifact generated at build time by
# challenge_files/generate.py and served from /files/<name>.
CHALLENGES += [
    # ═══ Network Traffic Analysis ═══════════════════════════════════════════
    {
        "id": 21, "title": "21 · Cleartext Credentials",
        "category": "Traffic Analysis", "module": "network",
        "skill": "Finding credentials in unencrypted traffic",
        "story": "An operator logged into the plant HMI portal over plain HTTP. "
                 "You have the packet capture.<br><br>"
                 "Download <a href='/files/portal_capture.pcap'>portal_capture.pcap</a> and open it in "
                 "Wireshark (or use <code>tshark</code>). Two separate TCP conversations are in there. "
                 "One of them carries the operator's password in the clear.<br><br>"
                 "The password <i>is</i> the flag.",
        "flag": "FLAG{cleartext_http_leaks_creds}",
        "points": 150,
        "notes": [
            ("Why HTTP is fatal here", "HTTP has no transport encryption, so every field of every form — usernames, passwords, session cookies, API keys — travels as readable ASCII. Anyone on the path (a switch SPAN port, a compromised router, a laptop on the same Wi-Fi) reads it without any decryption at all."),
            ("Where to look first", "Filter for <code>http.request.method == \"POST\"</code>. GET requests put parameters in the URL; POSTs put them in the body. Login forms are almost always POSTs, so that one filter cuts a large capture down to the interesting packets instantly."),
            ("Real-world context", "This is still routinely found on internal networks, especially on OT and building-management kit whose web interfaces predate TLS being free. Internal does not mean private: an attacker's first move after gaining a foothold is to capture traffic and harvest exactly this."),
            ("Key tools", "Wireshark &rarr; <i>File &gt; Open</i>, then <b>Follow &gt; HTTP Stream</b> &nbsp;·&nbsp; <code>tshark -r file.pcap -Y 'http.request.method==\"POST\"'</code> &nbsp;·&nbsp; <code>tcpdump -A -r file.pcap</code> &nbsp;·&nbsp; the <code>credslayer</code> and <code>PCredz</code> tools automate this"),
        ],
    },
    {
        "id": 22, "title": "22 · Stream Reassembly",
        "category": "Traffic Analysis", "module": "network",
        "skill": "Reassembling data split across TCP segments",
        "story": "A maintenance relay handed a key to a client, but the server sent it a few bytes at a "
                 "time. Searching individual packets for it will fail — no single packet contains the "
                 "whole string.<br><br>"
                 "Download <a href='/files/relay_session.pcap'>relay_session.pcap</a>. You need TCP to "
                 "reassemble the conversation before you can read it.",
        "flag": "FLAG{follow_the_whole_stream}",
        "points": 150,
        "notes": [
            ("Why packets aren't messages", "TCP is a byte stream, not a message protocol. The sender writes bytes; the stack splits them into segments wherever it likes, based on MSS, Nagle's algorithm and timing. A single application-level string can be spread across any number of packets — so grepping packets is not the same as reading data."),
            ("Reassembly is the whole point", "Wireshark's <b>Follow TCP Stream</b> sorts segments by sequence number, drops retransmissions and concatenates the payloads, giving you what the application actually saw. This is why an analyst follows streams instead of reading the packet list."),
            ("Real-world context", "Attackers rely on this gap deliberately. Splitting a payload or a command across segments defeats naive signature matching that inspects one packet at a time — which is precisely why real IDS engines perform stream reassembly before matching."),
            ("Key tools", "Wireshark &rarr; right-click a packet &rarr; <b>Follow &gt; TCP Stream</b> &nbsp;·&nbsp; <code>tshark -r file.pcap -qz follow,tcp,ascii,0</code> &nbsp;·&nbsp; <code>tcpflow</code> writes each direction of each stream to its own file"),
        ],
    },
    {
        "id": 23, "title": "23 · DNS Exfiltration",
        "category": "Exfiltration", "module": "network",
        "skill": "Spotting and decoding data smuggled through DNS",
        "story": "A workstation on the plant network made a burst of odd DNS lookups to a domain nobody "
                 "recognises. The queries never resolve to anything useful — the <i>names themselves</i> "
                 "are the message.<br><br>"
                 "Download <a href='/files/dns_traffic.pcap'>dns_traffic.pcap</a>. Most of the lookups are "
                 "ordinary plant hostnames. A handful are not. Pull out the suspicious subdomain labels, "
                 "put them back in order, and decode them.",
        "flag": "FLAG{dns_is_an_exfil_channel}",
        "points": 200,
        "notes": [
            ("Why DNS is the favourite channel", "DNS is almost never blocked outbound, is rarely inspected as deeply as HTTP, and every host is expected to make constant queries. A client that cannot reach the internet directly can still usually get a name resolved — and a resolved name means an attacker-controlled server received whatever was in it."),
            ("What the pattern looks like", "Long random-looking labels, high query volume to one domain, unique names every single time (so nothing ever hits cache), and queries with no matching user activity. Here the data is hex-encoded in the leftmost label and the next label is a sequence counter — the counter exists because UDP can reorder, so the receiver needs to reassemble."),
            ("Real-world context", "This is a standard C2 and exfiltration technique: <code>iodine</code> and <code>dnscat2</code> build full tunnels this way, and it was how the SolarWinds implant beaconed. Defenders hunt it with entropy scoring on query names, counts of unique subdomains per domain, and query-length baselines."),
            ("Key tools", "<code>tshark -r file.pcap -T fields -e dns.qry.name</code> &nbsp;·&nbsp; Wireshark &rarr; <i>Statistics &gt; DNS</i> &nbsp;·&nbsp; <code>xxd -r -p</code> to un-hex &nbsp;·&nbsp; CyberChef &rarr; 'From Hex'"),
        ],
    },
    {
        "id": 24, "title": "24 · Scan Signatures",
        "category": "Network Recon", "module": "network",
        "skill": "Recognising a port scan and what the attacker found",
        "story": "The IDS flagged a host as 'scanning'. Confirm it from the capture, then work out what the "
                 "attacker got.<br><br>"
                 "Download <a href='/files/scan_capture.pcap'>scan_capture.pcap</a>. One host sprays SYNs "
                 "across a list of ports; almost all are refused. Find the one port that <i>accepted</i> "
                 "the connection — the attacker came back to it, and the service introduced itself.",
        "flag": "FLAG{banner_grab_after_the_scan}",
        "points": 175,
        "notes": [
            ("How a SYN scan looks on the wire", "The scanner sends a SYN to each port and never completes the handshake. A <b>RST/ACK</b> back means closed; a <b>SYN/ACK</b> means open. One source IP, one destination, many destination ports, in rapid succession, with no data transferred is the signature — and it's why this is also called a half-open scan."),
            ("Open ports are the lead, banners are the prize", "Knowing a port is open is worth little; knowing <i>what is listening</i> is worth a lot. Many services announce their name and version on connect. That banner tells an attacker exactly which exploit to reach for, which is why banner grabbing immediately follows a scan."),
            ("Real-world context", "Everything internet-facing is scanned continuously — Shodan and Censys scan the whole IPv4 space on a schedule. On an internal network a scan is a much stronger signal: legitimate hosts don't enumerate their neighbours' ports, so this is often the first observable step of an intrusion."),
            ("Key tools", "<code>tshark -r f.pcap -Y 'tcp.flags.syn==1 &amp;&amp; tcp.flags.ack==1'</code> finds open ports &nbsp;·&nbsp; Wireshark &rarr; <i>Statistics &gt; Conversations</i> &nbsp;·&nbsp; <code>nmap -sS</code> generates this pattern &nbsp;·&nbsp; <code>nc</code> or <code>telnet</code> to grab a banner by hand"),
        ],
    },

    # ═══ Log Analysis & Detection ═══════════════════════════════════════════
    {
        "id": 25, "title": "25 · Brute Force in the Logs",
        "category": "Authentication Logs", "module": "logs",
        "skill": "Finding the successful login inside a brute-force attack",
        "story": "A jump host was hammered with SSH login attempts overnight. Most failed. "
                 "<b>One did not.</b><br><br>"
                 "Download <a href='/files/auth.log'>auth.log</a>. Find the account the attacker "
                 "successfully logged into, then read the session marker logged right after it.<br><br>"
                 "The hard part isn't the volume — it's that the success looks exactly like the failures "
                 "unless you filter for it.",
        "flag": "FLAG{one_success_among_the_failures}",
        "points": 150,
        "notes": [
            ("Failures are noise, the success is the incident", "A hundred failed logins is an attack <i>attempt</i>, and on its own it is routine background noise on anything reachable. A single <code>Accepted password</code> from the same source turns it into a <b>breach</b>. Triage means finding the state change, not counting the noise."),
            ("How to cut it down", "Separate by outcome and by source. <code>grep 'Failed password'</code> establishes the attack and its source IP; <code>grep 'Accepted'</code> for that same IP finds the compromise. Then pivot: once you have the account, every later log line mentioning it is in scope."),
            ("Real-world context", "This is the classic SSH story for any host with password auth on a public IP. The defences are well understood and cheap: key-only authentication, <code>fail2ban</code>, rate limiting, and alerting specifically on <i>success following repeated failure</i> — which is the detection rule this challenge teaches."),
            ("Key tools", "<code>grep</code>, <code>awk</code>, <code>sort | uniq -c | sort -rn</code> to rank source IPs &nbsp;·&nbsp; <code>lnav</code> for interactive log browsing &nbsp;·&nbsp; in a SIEM this is a correlation rule: N failures then 1 success from one source"),
        ],
    },
    {
        "id": 26, "title": "26 · Reading Status Codes",
        "category": "Web Logs", "module": "logs",
        "skill": "Finding the request that worked in a web access log",
        "story": "Someone ran a directory scanner against the plant portal. Almost every request got a "
                 "<code>404</code> — but not every one.<br><br>"
                 "Download <a href='/files/access.log'>access.log</a>. Find the scanner's single "
                 "<code>200</code> response. That one request found something it shouldn't have, and the "
                 "flag is in it.",
        "flag": "FLAG{read_the_status_codes}",
        "points": 150,
        "notes": [
            ("The status code is the verdict", "In a scan log the path tells you what was <i>tried</i>; the status code tells you what <i>exists</i>. Hundreds of 404s are a scanner finding nothing. A 200 among them is a real file — and a 403 is arguably more interesting still, because it means the path exists but is protected."),
            ("Reading the combined log format", "Fields are: client IP, identd, user, timestamp, request line, <b>status</b>, bytes, referrer, user-agent. The status is field 9 in <code>awk</code> terms, which makes <code>awk '$9==200'</code> the whole trick. The user-agent is your other lead — real scanners rarely bother to disguise it."),
            ("Real-world context", "Every public web server sees this traffic constantly. The job is separating background scanning from a scan that <i>succeeded</i>. Backup files, <code>.git</code> directories, <code>.env</code> files and stale admin panels are the usual finds, and each one leaks credentials or source code."),
            ("Key tools", "<code>awk '$9==200' access.log</code> &nbsp;·&nbsp; <code>awk '{print $9}' access.log | sort | uniq -c</code> for a status breakdown &nbsp;·&nbsp; <code>goaccess</code> for a live report &nbsp;·&nbsp; <code>gobuster</code>/<code>ffuf</code> are what generate this pattern"),
        ],
    },
    {
        "id": 27, "title": "27 · Impossible Travel",
        "category": "Authentication Logs", "module": "logs",
        "skill": "Detecting account compromise from session geography",
        "story": "A VPN session log looks normal at a glance — everyone connecting from the usual places. "
                 "But one account authenticated from two locations that no human could travel between in "
                 "the time available.<br><br>"
                 "Download <a href='/files/vpn_sessions.log'>vpn_sessions.log</a>, find that account, and "
                 "read the note logged on its anomalous session.",
        "flag": "FLAG{two_countries_one_minute}",
        "points": 175,
        "notes": [
            ("Why this detection works", "Credentials can be stolen and replayed from anywhere, but a person occupies one place at a time. Two successful authentications for one identity, far enough apart that the travel is physically impossible in the elapsed time, means more than one party is using that identity. It needs no malware signature and no payload — just geometry."),
            ("What to compute", "Group by user, then look for a geo or ASN change between consecutive successful authentications and divide distance by elapsed time. Here one account appears in two countries 48 seconds apart. Watch for the benign explanations too: VPNs, mobile carrier CGNAT, and cloud-hosted mail clients all produce false positives."),
            ("Real-world context", "'Impossible travel' is a built-in detection in Entra ID Identity Protection, Okta ThreatInsight and most SIEMs, and it is one of the highest-fidelity signals available for credential theft. It is also why the follow-on action matters: note the privilege-escalation request logged moments later."),
            ("Key tools", "<code>awk -F, '{print $2, $4}' | sort -u</code> to find accounts with more than one geo &nbsp;·&nbsp; MaxMind GeoIP for IP&rarr;location &nbsp;·&nbsp; in a SIEM: a geo-velocity or 'atypical travel' rule"),
        ],
    },
    {
        "id": 28, "title": "28 · The Log That Remembers",
        "category": "Anti-Forensics", "module": "logs",
        "skill": "Recovering evidence an attacker tried to destroy",
        "story": "An attacker cleared the audit trail on their way out. The live log starts suspiciously "
                 "late and the interesting hours are simply gone.<br><br>"
                 "But logs rotate. Download both <a href='/files/plant_syslog.log'>plant_syslog.log</a> and "
                 "<a href='/files/plant_syslog.log.1'>plant_syslog.log.1</a>. What was wiped from the live "
                 "file is still sitting in the rotated copy, including the marker written just before the "
                 "clear.",
        "flag": "FLAG{rotated_logs_remember}",
        "points": 200,
        "notes": [
            ("Clearing logs is itself evidence", "An empty or truncated log is not the absence of an incident — it <i>is</i> the incident. A gap where there should be entries, a timestamp sequence that jumps, or an audit daemon reporting its own rotation are all signals. Attackers clear logs precisely because logs are the record, which makes the clearing the loudest thing they do."),
            ("Why copies survive", "Log data exists in more places than the file being tailed: rotated and compressed archives (<code>.log.1</code>, <code>.gz</code>), the systemd journal, a remote syslog collector, SIEM ingestion, and unlinked file handles still held by a running process. Destroying one copy rarely destroys them all — which is the entire argument for shipping logs off-host in real time."),
            ("Real-world context", "Clearing the Windows Event Log is MITRE ATT&CK T1070.001 — <i>Indicator Removal</i>. Mature environments forward logs to a write-only collector the moment they're written, so an attacker with root on the host still cannot reach the authoritative copy. That design decision is what turns this technique from effective into noisy."),
            ("Key tools", "<code>ls -la /var/log/</code> to spot rotated files &nbsp;·&nbsp; <code>zgrep</code> to search compressed archives &nbsp;·&nbsp; <code>journalctl --verify</code> &nbsp;·&nbsp; <code>lsof +L1</code> finds deleted-but-open files &nbsp;·&nbsp; filesystem timeline tools (<code>fls</code>, <code>mactime</code>)"),
        ],
    },

    # ═══ Phishing & Email Forensics ═════════════════════════════════════════
    {
        "id": 29, "title": "29 · Following the Hops",
        "category": "Email Headers", "module": "phishing",
        "skill": "Tracing an email's true origin through Received headers",
        "story": "A convincing 'IT Helpdesk' email asks an operator to renew a VPN certificate. The "
                 "<code>From:</code> address looks plausible. The <code>Received:</code> headers tell a "
                 "different story.<br><br>"
                 "Download <a href='/files/phish_01.eml'>phish_01.eml</a> and read the hop chain from the "
                 "bottom up to find where the message really entered. That originating relay added a note "
                 "of its own.",
        "flag": "FLAG{received_headers_dont_lie}",
        "points": 150,
        "notes": [
            ("Read Received headers bottom-up", "Each mail server <i>prepends</i> its own <code>Received:</code> line, so the stack reads newest-at-the-top. The <b>bottom-most</b> Received header is the earliest hop — the closest thing you have to the true origin. Working upward traces the delivery path hop by hop."),
            ("What can and cannot be trusted", "<code>From:</code>, <code>Reply-To:</code> and the display name are free text the sender chooses — they prove nothing. Received headers added by <i>your own</i> infrastructure are trustworthy; ones added before the message reached you can be forged. So trust narrows as you read downward, and the handoff into your own perimeter is the key line."),
            ("Real-world context", "This is the first step of nearly every phishing triage. Mismatches between the claimed sender domain and the originating infrastructure, a <code>Message-ID</code> whose domain doesn't match the From, and a sending country inconsistent with the supposed sender are all standard findings in a real report."),
            ("Key tools", "Any mail client's 'Show Original' / 'View Source' &nbsp;·&nbsp; Google's Message Header Analyzer &nbsp;·&nbsp; MXToolbox Header Analyzer &nbsp;·&nbsp; <code>python3 -c 'import email; ...'</code> &nbsp;·&nbsp; <code>grep -i '^received'</code>"),
        ],
    },
    {
        "id": 30, "title": "30 · When Everything Fails",
        "category": "Email Headers", "module": "phishing",
        "skill": "Reading SPF, DKIM and DMARC results",
        "story": "A 'Payroll Services' email claims to come from <code>bnl.gov</code> and wants a direct "
                 "deposit form signed. The receiving mail server already checked whether that claim is "
                 "true, and wrote the answer in the headers.<br><br>"
                 "Download <a href='/files/phish_02.eml'>phish_02.eml</a> and read the "
                 "<code>Authentication-Results</code> header. All three checks failed — and the auditing "
                 "note alongside them is the flag.",
        "flag": "FLAG{spf_dkim_dmarc_all_failed}",
        "points": 175,
        "notes": [
            ("What the three checks actually do", "<b>SPF</b> asks whether the sending IP is authorised to send for the envelope domain. <b>DKIM</b> verifies a cryptographic signature over the message, proving it wasn't altered and really came from the signing domain. <b>DMARC</b> ties them together: it requires SPF or DKIM to pass <i>and align</i> with the visible <code>From:</code> domain, and publishes what to do on failure."),
            ("Why alignment is the crux", "An attacker can trivially pass SPF for a domain they own — <code>evil.com</code> can publish any SPF record it likes. What they cannot do is pass an <i>aligned</i> check for <code>bnl.gov</code> without controlling its DNS or signing key. That is why <code>dmarc=fail</code> on a message claiming a real organisation is close to conclusive."),
            ("Real-world context", "A <code>p=reject</code> DMARC policy means the owner has explicitly asked receivers to refuse failures — so a failing message that still landed in a mailbox points at a gap in the receiving side's enforcement. Treating these headers as the first filter is what keeps domain-spoofed phishing out of inboxes at scale."),
            ("Key tools", "<code>grep -iA5 'authentication-results'</code> &nbsp;·&nbsp; <code>dig TXT _dmarc.domain.com</code> and <code>dig TXT domain.com</code> to read the published policy &nbsp;·&nbsp; MXToolbox SPF/DMARC checkers &nbsp;·&nbsp; DMARC aggregate (RUA) reports"),
        ],
    },
    {
        "id": 31, "title": "31 · Hover Before You Click",
        "category": "Social Engineering", "module": "phishing",
        "skill": "Separating link text from link destination",
        "story": "A 'Microsoft 365' notice says three messages are in quarantine. It even shows a genuine "
                 "<code>login.microsoftonline.com</code> URL as reassurance.<br><br>"
                 "Download <a href='/files/phish_03.eml'>phish_03.eml</a> and look at the raw HTML. One "
                 "link displays one thing and points somewhere else entirely. The real destination carries "
                 "the flag.",
        "flag": "FLAG{hover_before_you_click}",
        "points": 150,
        "notes": [
            ("Anchor text is not the destination", "In HTML, <code>&lt;a href=\"X\"&gt;Y&lt;/a&gt;</code> displays <b>Y</b> but navigates to <b>X</b>. Nothing requires them to match, so a link can display a perfect real URL and lead anywhere. This is the single most-used deception in phishing because it defeats 'just look at the link' advice."),
            ("The decoy pattern", "Note the structure here: one <i>genuine</i> Microsoft link is included alongside the malicious one. Real links raise the message's credibility and help it past reputation filters, while the payload hides behind innocuous display text like 'Review messages'. Always enumerate <i>every</i> href, not just the obvious one."),
            ("Real-world context", "The same trick extends to homoglyph domains (<code>micr0soft.com</code>, Cyrillic lookalikes), deeply nested subdomains that push the real domain off the end of a mobile address bar, open redirects on legitimate sites, and URL shorteners. Checking the <i>registrable</i> domain — the last two labels before the TLD — is the habit that survives all of them."),
            ("Key tools", "Hover and read the status bar; long-press on mobile &nbsp;·&nbsp; <code>grep -o 'href=\"[^\"]*\"'</code> on the raw source &nbsp;·&nbsp; VirusTotal and urlscan.io for safe detonation &nbsp;·&nbsp; CyberChef 'Defang URL' before sharing an IOC"),
        ],
    },
    {
        "id": 32, "title": "32 · Decoding the Attachment",
        "category": "Malware Delivery", "module": "phishing",
        "skill": "Extracting and decoding a MIME attachment safely",
        "story": "An 'overdue invoice' email carries an attachment. Note the filename carefully — it ends in "
                 "<code>.pdf.bat</code>, which is not a PDF at all.<br><br>"
                 "Download <a href='/files/phish_04.eml'>phish_04.eml</a>. The attachment is base64-encoded "
                 "inside the message. Decode it <b>without running it</b> and read the marker in the script.",
        "flag": "FLAG{attachments_decode_to_payloads}",
        "points": 200,
        "notes": [
            ("How MIME carries files", "Email is 7-bit ASCII by design, so binaries are base64-encoded into a <code>multipart/mixed</code> body with boundary markers between parts. An attachment is therefore just text in the message source — which means you can extract and inspect it with no risk of execution, as long as you decode rather than open."),
            ("The double extension", "Windows hides known extensions by default, so <code>invoice_8871.pdf.bat</code> displays as <code>invoice_8871.pdf</code> with a PDF-looking icon. The user believes they are opening a document and instead run a batch script. The same trick appears with <code>.pdf.exe</code>, <code>.doc.js</code>, <code>.xlsx.lnk</code>, and with right-to-left override characters to reverse the visible extension."),
            ("Real-world context", "Analysts detonate attachments only in isolated sandboxes; static extraction first is the standard discipline. Here the payload is a stub invoking <code>powershell -nop -w hidden -enc</code> — hidden-window, encoded-command PowerShell is one of the most reliable malicious indicators on Windows, and the reason script-block logging exists."),
            ("Key tools", "<code>python3 -c 'import email; ...'</code> or the <code>email</code> module's <code>walk()</code> &nbsp;·&nbsp; <code>munpack</code> &nbsp;·&nbsp; <code>base64 -d</code> &nbsp;·&nbsp; <code>oletools</code> (<code>olevba</code>) for Office macros &nbsp;·&nbsp; <b>never</b> double-click; use a VM with no network"),
        ],
    },

    # ═══ OT / ICS Fundamentals ══════════════════════════════════════════════
    {
        "id": 33, "title": "33 · Reading Modbus",
        "category": "Industrial Protocols", "module": "ot",
        "skill": "Interpreting Modbus/TCP traffic",
        "story": "This is an HMI polling a PLC — the most ordinary traffic in a plant. Your job is to learn "
                 "to read it.<br><br>"
                 "Download <a href='/files/modbus_poll.pcap'>modbus_poll.pcap</a>. Most of it is a repeated "
                 "<i>Read Holding Registers</i> loop. One exchange is different: a device-identification "
                 "request whose response carries a string. That string is the flag.<br><br>"
                 "Notice what you <b>don't</b> see anywhere in this capture: any authentication at all.",
        "flag": "FLAG{modbus_has_no_authentication}",
        "points": 200,
        "notes": [
            ("How Modbus/TCP is framed", "A 7-byte MBAP header (transaction ID, protocol ID, length, unit ID) followed by a PDU: one function code plus its data. Function <code>0x03</code> reads holding registers, <code>0x01</code> reads coils, <code>0x05</code> writes a single coil, <code>0x06</code> writes a single register. Wireshark dissects TCP port 502 automatically, so the function codes are readable without any manual decoding."),
            ("Designed in 1979, with no security", "Modbus has no authentication, no authorisation, no encryption and no integrity checking. Any host that can reach port 502 can issue any command, and the PLC will carry it out — not because it is misconfigured, but because the protocol has no concept of a credential. Security has to come entirely from the network around it."),
            ("Real-world context", "Modbus still runs an enormous amount of industrial plant, power distribution and building management. You cannot patch the protocol, so defence is architectural: segmentation into Purdue-model zones, a conduit through a firewall or data diode, strict allow-lists of which hosts may talk to which PLCs, and passive monitoring that alerts on any unexpected function code."),
            ("Key tools", "Wireshark's <code>modbus</code> dissector &nbsp;·&nbsp; <code>tshark -Y 'modbus'</code> &nbsp;·&nbsp; <code>-e modbus.func_code -e modbus.reference_num</code> as fields &nbsp;·&nbsp; the <code>pymodbus</code> library &nbsp;·&nbsp; <code>plcscan</code>, and Nmap's <code>modbus-discover</code> script"),
        ],
    },
    {
        "id": 34, "title": "34 · The Coil That Opened a Breaker",
        "category": "Industrial Protocols", "module": "ot",
        "skill": "Recognising an unauthenticated control-write attack",
        "story": "At 05:13 a breaker on BUS-2 opened and 1,180 kW of load was shed. No operator touched it."
                 "<br><br>"
                 "Download <a href='/files/modbus_write.pcap'>modbus_write.pcap</a> and "
                 "<a href='/files/breaker_alarm.log'>breaker_alarm.log</a>. An external address wrote "
                 "directly to a coil and the PLC simply obeyed. Correlate the write in the capture with the "
                 "alarm journal and read the acknowledgement token.",
        "flag": "FLAG{coil_forced_breaker_opened}",
        "points": 250,
        "notes": [
            ("Read is reconnaissance, write is impact", "The attacker reads coils first to learn the current state, then issues <b>Write Single Coil</b> (function <code>0x05</code>, value <code>0xFF00</code> for ON) and re-reads to confirm the change took effect. That read-write-verify pattern is the signature of someone manipulating a process rather than merely observing it — and it is the point at which a network intrusion becomes a physical event."),
            ("Why correlation matters", "The capture proves a command was sent; the alarm journal proves the plant <i>moved</i>. Neither alone is the whole story — an IT analyst sees a packet, an operator sees a breaker trip. Incident response in OT only works when both timelines are laid side by side, which is why timestamp discipline across IT and OT systems is a prerequisite."),
            ("Real-world context", "This is the mechanism behind the 2015 and 2016 Ukrainian grid attacks, where attackers operated breakers through legitimate control protocols. No exploit and no malware on the PLC were required — only reachability. That is why 'can this host reach port 502?' is the single most important question in an OT network review."),
            ("Key tools", "<code>tshark -Y 'modbus.func_code==5'</code> isolates coil writes &nbsp;·&nbsp; Wireshark &rarr; <i>Statistics &gt; Conversations</i> to spot an unexpected peer &nbsp;·&nbsp; Zeek with industrial protocol parsers &nbsp;·&nbsp; passive OT monitoring (Nozomi, Claroty, Dragos) alerts on first-seen write commands"),
        ],
    },
    {
        "id": 35, "title": "35 · Telnet to a PLC",
        "category": "OT Access", "module": "ot",
        "skill": "Recovering credentials from legacy cleartext protocols",
        "story": "A PLC gateway still exposes Telnet. Someone logged into it from an external address, and "
                 "the whole session — username, password, everything after — crossed the network in the "
                 "clear.<br><br>"
                 "Download <a href='/files/plc_telnet.pcap'>plc_telnet.pcap</a>. Telnet sends each keystroke "
                 "in its own packet, so you will need to reassemble the conversation. The session key the "
                 "gateway issued on success is the flag.",
        "flag": "FLAG{telnet_to_a_plc_in_2026}",
        "points": 225,
        "notes": [
            ("Telnet is a plaintext terminal", "Telnet predates any notion of transport security: every keystroke and every byte of output travels unencrypted. Because it sends character-by-character rather than line-by-line, a password appears as a column of one-byte packets — invisible to a per-packet grep, obvious the moment you reassemble the stream."),
            ("Why it is still running", "A PLC or gateway may have a 20-year service life, a vendor that no longer exists, and a maintenance window measured in minutes per year. 'Just turn Telnet off' can mean a firmware upgrade that voids certification or a process shutdown — so the honest mitigation is usually compensating controls: a jump host, strict allow-lists, and monitoring for any connection to port 23."),
            ("Real-world context", "Shodan returns large numbers of internet-exposed industrial devices speaking Telnet, FTP and SNMPv1. The same reassembly technique recovers FTP and POP3 credentials, SNMP community strings, and unencrypted HTTP basic-auth headers. Finding one of these on an internal network is a finding in its own right, before anyone exploits it."),
            ("Key tools", "Wireshark &rarr; <b>Follow &gt; TCP Stream</b> &nbsp;·&nbsp; <code>tshark -qz follow,tcp,ascii,0</code> &nbsp;·&nbsp; the <code>telnet</code> dissector reassembles keystrokes &nbsp;·&nbsp; <code>nmap -p23 --script telnet-encryption</code> &nbsp;·&nbsp; replace with SSH, or front it with a bastion"),
        ],
    },
    {
        "id": 36, "title": "36 · Safety Outranks Uptime",
        "category": "OT Risk", "module": "ot",
        "skill": "Applying the SRP triad to an OT change decision",
        "story": "IT security optimises for <b>confidentiality first</b>. OT does not. In a plant the "
                 "ordering is <b>Safety &rarr; Reliability &rarr; Performance</b> — the SRP triad — because "
                 "the worst outcome here isn't a data breach, it's someone getting hurt.<br><br>"
                 "Download <a href='/files/hmi_station.conf'>hmi_station.conf</a>. Read the change-control "
                 "and interlock sections, and note how many findings this one file contains "
                 "(<code>auth = none</code>, <code>allow_from = 0.0.0.0/0</code>, never patched). The "
                 "<code>srp_precedence</code> value states the ordering — that's the flag.",
        "flag": "FLAG{safety_outranks_uptime}",
        "points": 275,
        "notes": [
            ("Why the triad inverts in OT", "IT protects information: confidentiality, integrity, availability. OT protects a physical process, where availability and integrity come first because the failure mode is a release, a fire or an injury — not a disclosure. Taking a running plant offline 'to be safe' can itself be the unsafe action, which is why patching habits that are obvious in IT are genuinely wrong here."),
            ("Interlocks are not obstacles", "An interlock exists to make a dangerous state physically unreachable. Bypassing an overpressure trip to hit a production target trades <b>Safety</b> for <b>Performance</b> — an inversion of the ordering, and never a decision an individual operator is authorised to make. Hence <code>bypass_requires = two-person authorization</code>: the control is procedural because the consequence is physical."),
            ("Reading this file as an assessor", "Four findings sit in plain sight: <code>auth = none</code> on a writable control protocol, <code>allow_from = 0.0.0.0/0</code> so any plant host may command it, <code>patch_window = none</code>, and an unauthenticated write path to equipment with real-world effects. Note that the first is a property of Modbus itself — the <i>fixable</i> finding is the reachability, which is why segmentation does the heavy lifting."),
            ("Real-world context", "This framing drives IEC 62443 zones and conduits, the Purdue model, and why OT change control is deliberately slow. It is also why safety instrumented systems (SIS) are kept physically separate from the control network: so that compromising the DCS still cannot defeat the layer whose only job is to prevent harm."),
        ],
    },
]


# ── Modules / tracks ──────────────────────────────────────────────────────────
# The ladder outgrew a single grid at ~20 cards, so challenges are grouped into
# tracks. `module` on each challenge is the slug; anything without one falls back
# to "foundations" (the original 20).
MODULES = [
    {
        "slug": "foundations", "name": "Foundations", "icon": "🎓",
        "level": "Start here",
        "blurb": "Encoding, recon, file analysis, crypto, web, auth and injection. "
                 "Builds the vocabulary every other track assumes.",
    },
    {
        "slug": "network", "name": "Network Traffic Analysis", "icon": "🌐",
        "level": "Core skill",
        "blurb": "Read real packet captures in Wireshark: harvest cleartext credentials, "
                 "reassemble TCP streams, decode DNS exfiltration, read a port scan.",
    },
    {
        "slug": "logs", "name": "Log Analysis & Detection", "icon": "📊",
        "level": "Defensive",
        "blurb": "The blue-team track. Find the one success in a brute force, the 200 among "
                 "the 404s, impossible travel, and evidence an attacker tried to destroy.",
    },
    {
        "slug": "phishing", "name": "Phishing & Email Forensics", "icon": "📧",
        "level": "Defensive",
        "blurb": "Triage real .eml files: trace Received hops to the true origin, read "
                 "SPF/DKIM/DMARC, unmask deceptive links, decode attachments safely.",
    },
    {
        "slug": "ot", "name": "OT / ICS Fundamentals", "icon": "🏭",
        "level": "Specialist",
        "blurb": "Industrial control systems: read Modbus, watch an unauthenticated write "
                 "open a breaker, pull credentials off Telnet, and apply the SRP triad.",
    },
]
MODULE_BY_SLUG = {m["slug"]: m for m in MODULES}
DEFAULT_MODULE = "foundations"

# Documents served by the /docs tab (also used for per-challenge further reading).
APP_DIR = os.path.dirname(os.path.abspath(__file__))
DOCS_DIR = os.path.join(APP_DIR, "docs")
# Challenge artifacts (captures, logs, .eml files) generated at build time.
FILES_DIR = os.path.join(APP_DIR, "challenge_files")

# ── Progressive hints ─────────────────────────────────────────────────────────
# Three tiers per challenge, each revealed only on click. The old always-visible
# "Hint:" line gave away the exact command before a student had tried anything;
# retrieval effort is where the learning happens, so the command is now the LAST
# resort rather than the first thing on the page.
#
# Tiers 1-2 are authored here. Tier 3 is lifted automatically from the inline
# "<b>Hint:</b>" that used to sit in the story, so no existing guidance is lost.
HINT_TIERS = {
    1: [("Nudge", "The string ends in <code>=</code>. That padding character is the signature of one specific encoding — which one?"),
        ("Method", "It's Base64. Every language and CyberChef can decode it, and on the command line the tool is named after it.")],
    2: [("Nudge", "Those pairs only ever use the digits 0-9 and the letters a-f. What numbering system has exactly 16 digits?"),
        ("Method", "Hexadecimal. Each pair of characters is one byte, and each byte is one ASCII character.")],
    3: [("Nudge", "Eight digits per group, nothing but 1s and 0s. Each group is a single character."),
        ("Method", "Each 8-bit group is an ASCII code point. Convert binary to decimal, then decimal to a character.")],
    4: [("Nudge", "The page shows you what it wants you to see. The file the browser built it from can hold more."),
        ("Method", "View the page source. Browsers parse comments but never display them, which makes them a classic hiding place.")],
    5: [("Nudge", "A response is more than its body. Every page arrives with a set of metadata you never see."),
        ("Method", "Read the HTTP response headers rather than the page content — DevTools' Network tab, or a request that prints headers only.")],
    6: [("Nudge", "Binary files still contain readable text. You just can't see it by opening them in a text editor."),
        ("Method", "There is a standard tool that extracts printable character sequences from any file. Pipe its output to a search.")],
    7: [("Nudge", "A file's extension is just part of its name. Nothing forces it to be honest."),
        ("Method", "Identify the file by its contents instead of its name, then open it with whatever program actually matches.")],
    8: [("Nudge", "Word lengths and the <code>FLAG{}</code> shape are intact — only the letters themselves changed. So each letter maps to exactly one other letter."),
        ("Method", "A fixed-shift substitution cipher. ROT13 rotates every letter 13 places through the alphabet.")],
    9: [("Nudge", "Same cipher as the last challenge, but the shift isn't 13. How many shifts are even possible?"),
        ("Method", "Only 25 useful shifts exist, so try all of them and read which output is English. That is brute force.")],
    10: [("Nudge", "The server asked your browser to remember something about who you are. You can read what it remembered."),
         ("Method", "DevTools &rarr; Application &rarr; Cookies. If the server trusts a cookie's value, editing that value changes what the server believes about you.")],
    11: [("Nudge", "Everything after the <code>?</code> in the address bar was sent by you, not decided by the server."),
         ("Method", "Edit the query string directly in the address bar and reload the page.")],
    12: [("Nudge", "Websites publish a file that tells search engine crawlers which paths to stay away from. That list is public."),
         ("Method", "Request <code>/robots.txt</code>. Anything marked Disallow is a path someone wanted kept out of search results.")],
    13: [("Nudge", "Not every page on a site is linked from somewhere. Common directory names are common for a reason."),
         ("Method", "Guess predictable paths by hand — the kind of name a developer would pick for old files they meant to delete.")],
    14: [("Nudge", "An image carries more than its pixels. Cameras and editing tools write information into the file itself."),
         ("Method", "Read the image's embedded metadata rather than viewing the picture.")],
    15: [("Nudge", "Every file format begins with a fixed signature. The extension claimed PDF — check what the first bytes actually say."),
         ("Method", "Dump the opening bytes in hex and compare them against known file signatures.")],
    16: [("Nudge", "Shipped hardware and software arrive with a password already set. Most people never change it."),
         ("Method", "Try the well-known default username and password pairs against the admin account.")],
    17: [("Nudge", "Your token isn't random — look closely at it. Does it decode into something meaningful?"),
         ("Method", "It's encoded, not encrypted. Decode it, change who it claims you are, then re-encode it the same way.")],
    18: [("Nudge", "This tool runs a real system command with your input placed inside it. What if your input ended that command early and started another?"),
         ("Method", "Shell metacharacters chain a second command onto the first. The flag sits in a file at the root of the filesystem.")],
    19: [("Nudge", "Your username is pasted straight into a database query. What if it contained query syntax instead of a name?"),
         ("Method", "Break out of the string literal, then either make the condition always true or comment out the password check entirely.")],
    20: [("Nudge", "Nothing in this one is new. It is three things you have already done, performed in sequence."),
         ("Method", "Start with recon to find a hidden path, decode what you find there, then pass the result along as a URL parameter.")],
}

# One line shown the moment a challenge is solved — the peak-attention moment,
# which previously displayed only a point total.
TAKEAWAYS = {
    1: "Base64 is encoding, not encryption. It hides nothing from anyone who recognizes it — treat it as plain text.",
    2: "Hex is how analysts read raw bytes. You will see it in packet captures, file headers and memory dumps for the rest of your career.",
    3: "Binary, hex and text are three views of the same bytes. Being able to move between them is a core analyst skill.",
    4: "Anything delivered to the browser is public. Comments, hidden fields and commented-out code all ship to the attacker.",
    5: "Headers carry authentication, caching and security policy. Reading them is the first step of almost every web assessment.",
    6: "Before anything clever, run strings. It is the single highest-yield first move on an unknown file.",
    7: "Never trust an extension. Malware delivery relies on people trusting the name instead of the contents.",
    8: "ROT13 is obfuscation, not cryptography. Preserved word shapes are the tell that a substitution cipher is in play.",
    9: "A tiny key space means no security. If the possibilities can be enumerated, they will be.",
    10: "Never trust client-side values. Anything the browser holds, the user can edit — the server must re-verify.",
    11: "User-supplied parameters are attacker-controlled input. Authorization has to be checked server-side, every request.",
    12: "robots.txt is a recon goldmine. It is a list of paths someone specifically wanted hidden.",
    13: "Unlinked does not mean inaccessible. Attackers enumerate paths with wordlists; obscurity is not access control.",
    14: "Metadata leaks more than people expect — GPS coordinates, usernames, software versions, internal paths.",
    15: "File signatures beat file names. This is how forensic tools identify evidence regardless of what it is called.",
    16: "Default credentials remain one of the most common real-world breaches. Changing them is the cheapest security win there is.",
    17: "Encoding is not authentication. Session tokens must be random and server-validated, never a decodable username.",
    18: "Unsanitized input reaching a shell is remote code execution. Never build shell commands from user input.",
    19: "Parameterized queries stop this cold. String-concatenated SQL is still breaching real companies today.",
    20: "Real intrusions are chains. Each step is individually small; the impact comes from linking them together.",
}

# Further reading per challenge, pointing at the PDFs already in docs/.
# Filenames are resolved against DOCS_DIR at import, so a renamed or removed PDF
# silently drops out of the UI instead of rendering a dead link.
DOC_LINKS = {
    1: ["What_is_a_CTF.pdf", "Beginner's Guide to Cyber & CTFs.pdf"],
    2: ["Beginner's Guide to Cyber & CTFs.pdf"],
    3: ["Beginner's Guide to Cyber & CTFs.pdf"],
    4: ["Beginner's Guide to Cyber & CTFs.pdf"],
    5: ["Beginner's Guide to Cyber & CTFs.pdf"],
    6: ["CTF_VM_Setup_Guide.pdf", "Beginner's Guide to Cyber & CTFs.pdf"],
    7: ["CTF_VM_Setup_Guide.pdf"],
    8: ["Beginner's Guide to Cyber & CTFs.pdf"],
    9: ["Beginner's Guide to Cyber & CTFs.pdf"],
    10: ["Think_Like_a_Hacker_CTF.pdf"],
    11: ["Think_Like_a_Hacker_CTF.pdf"],
    12: ["Think_Like_a_Hacker_CTF.pdf"],
    13: ["Think_Like_a_Hacker_CTF.pdf", "CTF_VM_Setup_Guide.pdf"],
    14: ["CTF_VM_Setup_Guide.pdf"],
    15: ["CTF_VM_Setup_Guide.pdf"],
    16: ["Think_Like_a_Hacker_CTF.pdf"],
    17: ["Think_Like_a_Hacker_CTF.pdf"],
    18: ["Think_Like_a_Hacker_CTF.pdf"],
    19: ["Think_Like_a_Hacker_CTF.pdf"],
    20: ["Think_Like_a_Hacker_CTF.pdf", "What_is_a_CTF.pdf"],
}

HINT_TIERS.update({
    21: [("Nudge", "Two TCP conversations are in this capture. One is just a page load; the other submits a form. Which HTTP method sends form data in the body?"),
         ("Method", "Filter for POST requests, then follow that HTTP stream and read the request body. The form fields are plain <code>name=value</code> pairs."),
         ("Exact command", "<code>tshark -r portal_capture.pcap -Y 'http.request.method==\"POST\"' -T fields -e urlencoded-form.value</code> &nbsp;or in Wireshark: filter <code>http.request.method == \"POST\"</code> then right-click &rarr; Follow &rarr; HTTP Stream")],
    22: [("Nudge", "Searching individual packets will fail here — that's the lesson. TCP is a byte stream, so where does the complete message exist?"),
         ("Method", "Let TCP reassemble the conversation: follow the stream and read the server's side of it in order."),
         ("Exact command", "In Wireshark: right-click any packet &rarr; <b>Follow &gt; TCP Stream</b>. On the command line: <code>tshark -r relay_session.pcap -qz follow,tcp,ascii,0</code>")],
    23: [("Nudge", "Most lookups are ordinary plant hostnames. A handful go to a domain that isn't — and their leftmost labels are long and hex-looking."),
         ("Method", "Extract every query name, keep the ones for the odd domain, take the first label of each in sequence order, concatenate them and decode from hex."),
         ("Exact command", "<code>tshark -r dns_traffic.pcap -Y 'dns.qry.name contains \"tunnel\"' -T fields -e dns.qry.name | cut -d. -f1 | tr -d '\\n' | xxd -r -p</code>")],
    24: [("Nudge", "In a SYN scan, a closed port answers RST/ACK and an open one answers SYN/ACK. Which port answered differently?"),
         ("Method", "Filter for packets with both SYN and ACK set to find the single open port, then follow the later conversation to that port and read the banner the service sent."),
         ("Exact command", "<code>tshark -r scan_capture.pcap -Y 'tcp.flags.syn==1 &amp;&amp; tcp.flags.ack==1' -T fields -e tcp.srcport</code> &nbsp;then follow the stream on that port (it's 8291)")],
    25: [("Nudge", "Hundreds of lines say <code>Failed password</code>. The incident is the line that doesn't."),
         ("Method", "Find the attacking IP from the failures, then search for <code>Accepted</code> from that same IP. The marker is logged on the next lines of that session."),
         ("Exact command", "<code>grep 'Accepted' auth.log</code> &nbsp;— then look at the lines immediately after the one from <code>203.0.113.47</code>")],
    26: [("Nudge", "The scanner's requests almost all returned 404. You want the one that didn't."),
         ("Method", "The status code is the 9th whitespace-separated field in the combined log format, so filter on it directly."),
         ("Exact command", "<code>awk '$9==200' access.log | grep 203.0.113.47</code>")],
    27: [("Nudge", "Group the log by user and look at where each one connected from. One account appears in two very different places."),
         ("Method", "List unique user + geo pairs to find the account with two locations, then read that account's consecutive session lines and the note on the anomalous one."),
         ("Exact command", "<code>awk -F, '{print $2, $4}' vpn_sessions.log | sort -u</code> &nbsp;then <code>grep m.okafor vpn_sessions.log</code>")],
    28: [("Nudge", "The live log is missing the hours you care about — and it says so. Where else does log data live on a Linux host?"),
         ("Method", "Logs rotate: yesterday's entries moved to a <code>.1</code> file before the clear. Search the rotated copy."),
         ("Exact command", "<code>grep -i marker plant_syslog.log.1</code> &nbsp;or just <code>cat plant_syslog.log.1</code>")],
    29: [("Nudge", "Each mail server adds its own <code>Received:</code> line to the top. So which end of the stack is the oldest hop?"),
         ("Method", "Read the Received headers from the bottom up. The earliest one is the originating relay — and it added an extra header of its own."),
         ("Exact command", "<code>grep -iA3 '^received' phish_01.eml | tail -12</code> &nbsp;— look at the bottom-most Received block")],
    30: [("Nudge", "The receiving mail server already did the work of checking whether the sender claim was genuine. It wrote the result down."),
         ("Method", "Read the <code>Authentication-Results</code> header. All three of SPF, DKIM and DMARC failed, and an audit note sits in the same header."),
         ("Exact command", "<code>grep -iA5 'authentication-results' phish_02.eml</code>")],
    31: [("Nudge", "The email shows you a real Microsoft URL. That's the decoy — look at where each link actually points, not what it displays."),
         ("Method", "Pull every <code>href</code> out of the raw HTML. One of them doesn't match its own anchor text at all."),
         ("Exact command", "<code>grep -o 'href=\"[^\"]*\"' phish_03.eml</code>")],
    32: [("Nudge", "The attachment is base64 text sitting in the message source. You never need to run it to read it."),
         ("Method", "Parse the MIME parts and decode the base64 body of the attachment, or copy the base64 block out and decode it by hand."),
         ("Exact command", "<code>python3 -I -c \"import email;m=email.message_from_file(open('phish_04.eml'));[print(p.get_payload(decode=True).decode()) for p in m.walk() if p.get_filename()]\"</code>")],
    33: [("Nudge", "Wireshark dissects port 502 as Modbus/TCP for you. Most packets are the same read loop — find the one exchange that isn't."),
         ("Method", "Filter on Modbus and compare function codes. The repeated ones are <code>0x03</code> (Read Holding Registers); the odd one out is a device-identification request whose reply carries a string."),
         ("Exact command", "<code>tshark -r modbus_poll.pcap -qz follow,tcp,ascii,0 | tail -5</code> &nbsp;or filter <code>modbus</code> in Wireshark and read the last response")],
    34: [("Nudge", "Function code <code>0x05</code> is Write Single Coil. Who sent one, and is that address supposed to be talking to a PLC at all?"),
         ("Method", "Isolate the coil write in the capture to confirm the command and its source, then line its timestamp up against the alarm journal and read the acknowledgement token."),
         ("Exact command", "<code>tshark -r modbus_write.pcap -Y 'modbus.func_code==5' -T fields -e ip.src -e modbus.reference_num</code> &nbsp;then <code>grep ack_token breaker_alarm.log</code>")],
    35: [("Nudge", "Telnet sends one keystroke per packet, so the password is never in any single packet. Same technique as challenge 22."),
         ("Method", "Follow the TCP stream to reassemble the whole session. You'll see the login, the password typed character by character, and the key the gateway issued on success."),
         ("Exact command", "<code>tshark -r plc_telnet.pcap -qz follow,tcp,ascii,0</code> &nbsp;— look for <code>session-key:</code>")],
    36: [("Nudge", "This one is about judgement, not tooling. Read the file's own comments — it tells you how to rank the three vertices."),
         ("Method", "Find the <code>[review]</code> section. It spells out the precedence order and stores it in a setting."),
         ("Exact command", "<code>grep srp_precedence hmi_station.conf</code>")],
})

TAKEAWAYS.update({
    21: "If it isn't encrypted, assume it's already been read. Internal networks are not private.",
    22: "Packets aren't messages. Reassemble the stream before you conclude something isn't there.",
    23: "DNS is a covert channel. If you only inspect HTTP, you are not inspecting egress.",
    24: "A scan tells an attacker what exists; a banner tells them what to exploit. Don't advertise versions.",
    25: "Failed logins are noise. One success after many failures is an incident — alert on the transition.",
    26: "In a scan log the path is what was tried; the status code is what exists. Read the codes.",
    27: "One identity cannot be in two places at once. Geo-velocity catches credential theft with no malware signature.",
    28: "A cleared log is evidence, not an absence of it. Ship logs off-host so the local copy stops being authoritative.",
    29: "From: is free text. Received headers added by your own infrastructure are the part you can trust.",
    30: "DMARC failure on a message claiming a real organisation is close to conclusive. Alignment is what matters.",
    31: "Link text and link destination are unrelated. Check the registrable domain, not the display text.",
    32: "Attachments are text in the message source — decode statically, never double-click. Double extensions hide intent.",
    33: "Modbus has no authentication by design. You cannot patch that, so the network has to provide it.",
    34: "Reachability is the vulnerability. If a host can reach port 502, it can operate the plant.",
    35: "Legacy cleartext protocols hand over credentials to anyone on the path. Front them with a bastion or remove them.",
    36: "In OT the order is Safety, then Reliability, then Performance. Anyone inverting it is making a decision that isn't theirs.",
})

DOC_LINKS.update({
    21: ["Getting_Started_with_Wireshark.pdf", "CTF_VM_Setup_Guide.pdf"],
    22: ["Getting_Started_with_Wireshark.pdf"],
    23: ["Getting_Started_with_Wireshark.pdf", "Think_Like_a_Hacker_CTF.pdf"],
    24: ["Getting_Started_with_Wireshark.pdf", "Think_Like_a_Hacker_CTF.pdf"],
    25: ["Think_Like_a_Hacker_CTF.pdf"],
    26: ["Think_Like_a_Hacker_CTF.pdf"],
    27: ["Think_Like_a_Hacker_CTF.pdf"],
    28: ["Think_Like_a_Hacker_CTF.pdf"],
    29: ["Analysts_Guide_to_Phishing_Emails.pdf"],
    30: ["Analysts_Guide_to_Phishing_Emails.pdf"],
    31: ["Analysts_Guide_to_Phishing_Emails.pdf"],
    32: ["Analysts_Guide_to_Phishing_Emails.pdf"],
    33: ["OT_101_From_IT_to_OT.pdf", "Getting_Started_with_Wireshark.pdf"],
    34: ["OT_101_From_IT_to_OT.pdf", "Getting_Started_with_Wireshark.pdf"],
    35: ["OT_101_From_IT_to_OT.pdf", "Getting_Started_with_Wireshark.pdf"],
    36: ["OT_101_From_IT_to_OT.pdf"],
})


_HINT_MARKER = "<b>Hint:</b>"


def _split_inline_hint(story):
    """Split a story into (body, trailing inline hint) on the legacy marker."""
    if _HINT_MARKER not in story:
        return story, ""
    body, _, hint = story.partition(_HINT_MARKER)
    body = body.rstrip()
    while body.endswith("<br>"):
        body = body[: -len("<br>")].rstrip()
    return body, hint.strip()


def _prepare_challenges():
    """Attach hints, takeaway and further-reading links to each challenge."""
    for c in CHALLENGES:
        body, inline_hint = _split_inline_hint(c["story"])
        c["story"] = body

        tiers = list(HINT_TIERS.get(c["id"], []))
        if inline_hint:
            tiers.append(("Exact command", inline_hint))
        c["hints"] = tiers

        c["takeaway"] = TAKEAWAYS.get(c["id"], "")
        c.setdefault("module", DEFAULT_MODULE)
        c["docs"] = [name for name in DOC_LINKS.get(c["id"], [])
                     if os.path.isfile(os.path.join(DOCS_DIR, name))]


_prepare_challenges()


# ── Anonymous aggregate stats (instructor view) ───────────────────────────────
# Process-local counters only: no identities, nothing written to disk, and the
# whole thing resets when the container restarts — i.e. per club meeting.
# Purpose is to show which challenge is burning the room, nothing about any
# individual student.
_STATS_LOCK = threading.Lock()
CHALLENGE_STATS = {c["id"]: {"attempts": 0, "solves": 0} for c in CHALLENGES}
SESSION_COUNT = {"total": 0}


def record_attempt(cid, correct):
    with _STATS_LOCK:
        row = CHALLENGE_STATS.get(cid)
        if row is None:
            return
        row["attempts"] += 1
        if correct:
            row["solves"] += 1


def record_session():
    with _STATS_LOCK:
        SESSION_COUNT["total"] += 1


def module_challenges(slug):
    return [c for c in CHALLENGES if c["module"] == slug]


def module_progress():
    """Per-track progress for the index: counts, points and percent complete."""
    solved = set(get_solved())
    out = []
    for m in MODULES:
        chs = module_challenges(m["slug"])
        pts = sum(c["points"] for c in chs)
        got = sum(c["points"] for c in chs if c["id"] in solved)
        done = sum(1 for c in chs if c["id"] in solved)
        out.append({**m, "count": len(chs), "solved": done, "points": pts,
                    "earned": got, "pct": round(got / pts * 100) if pts else 0})
    return out


def module_neighbours(c):
    """Previous/next challenge id within the same track (None at the ends)."""
    ids = [x["id"] for x in module_challenges(c["module"])]
    try:
        i = ids.index(c["id"])
    except ValueError:
        return None, None, 0, 0
    prev_id = ids[i - 1] if i > 0 else None
    next_id = ids[i + 1] if i < len(ids) - 1 else None
    return prev_id, next_id, i + 1, len(ids)


def header_ctx(active, show_stats=True):
    """Context every page's shared header needs."""
    solved = get_solved()
    return {
        "active": active,
        "show_stats": show_stats,
        "score": get_score(),
        "total": TOTAL_POINTS,
        "solved_count": len(solved),
        "total_challenges": TOTAL_CHALLENGES,
    }


def stats_rows():
    """Per-challenge aggregates, hardest-first by failed attempts per solve."""
    rows = []
    with _STATS_LOCK:
        for c in CHALLENGES:
            st = CHALLENGE_STATS[c["id"]]
            attempts, solves = st["attempts"], st["solves"]
            failures = attempts - solves
            # Failed attempts per solve: how much the room struggled to get there.
            friction = (failures / solves) if solves else (float(failures) if failures else 0.0)
            rows.append({
                "id": c["id"], "title": c["title"], "category": c["category"],
                "attempts": attempts, "solves": solves, "failures": failures,
                "friction": round(friction, 1),
                "rate": round(solves / attempts * 100) if attempts else 0,
            })
    rows.sort(key=lambda r: (-r["friction"], -r["failures"], r["id"]))
    return rows




FLAG_MAP = {c["flag"]: c["id"] for c in CHALLENGES}
TOTAL_POINTS = sum(c["points"] for c in CHALLENGES)
TOTAL_CHALLENGES = len(CHALLENGES)

# First-appearance order of categories, derived so a challenge in a brand-new
# category can never silently render nowhere (it used to be a hardcoded list).
CATEGORY_ORDER = list(dict.fromkeys(c["category"] for c in CHALLENGES))

# ── SQLite for flag 19 ────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect("/tmp/users.db")
    conn.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT, flag TEXT)")
    conn.execute("DELETE FROM users")
    conn.execute("INSERT INTO users VALUES ('admin','s3cr3tP@ss!','FLAG{sql_injection_bypasses_auth}')")
    conn.execute("INSERT INTO users VALUES ('guest','guest','no_flag_for_guests')")
    conn.commit()
    conn.close()

init_db()

# ── Helpers ───────────────────────────────────────────────────────────────────
def get_solved():
    return session.get("solved", [])

def mark_solved(flag):
    solved = get_solved()
    cid = FLAG_MAP.get(flag)
    if cid and cid not in solved:
        solved.append(cid)
        session["solved"] = solved
        return True, cid
    return False, cid

def get_score():
    solved = get_solved()
    return sum(c["points"] for c in CHALLENGES if c["id"] in solved)


# Characters that ride along on copy-paste from PDFs, terminals and chat apps.
_JUNK_CHARS = dict.fromkeys(map(ord, "\u200b\u200c\u200d\ufeff\u00a0"), None)
_QUOTE_MAP = str.maketrans({"\u2018": "'", "\u2019": "'",
                            "\u201c": '"', "\u201d": '"'})


def normalize_flag(raw):
    """Canonical form for comparison: strips invisible junk, smart quotes and case.

    Beginners lose far more attempts to copy-paste artifacts than to not knowing
    the answer, so format trivia should never be the obstacle.
    """
    text = (raw or "").strip().translate(_JUNK_CHARS).translate(_QUOTE_MAP)
    return " ".join(text.split()).casefold()


def flag_inner(flag):
    """The part inside FLAG{...}, so a wrapper-less answer can be recognized."""
    norm = normalize_flag(flag)
    if norm.startswith("flag{") and norm.endswith("}"):
        return norm[len("flag{"):-1]
    return norm


# Built once: canonical flag -> challenge id, and inner text -> challenge id.
NORM_FLAG_MAP = {normalize_flag(c["flag"]): c["id"] for c in CHALLENGES}
INNER_FLAG_MAP = {flag_inner(c["flag"]): c["id"] for c in CHALLENGES}


def grade_submission(submitted, challenge):
    """Return (is_correct, message) with a useful hint on near-misses."""
    guess = normalize_flag(submitted)
    if not guess:
        return False, "Enter a flag before submitting."

    if guess == normalize_flag(challenge["flag"]):
        return True, ""

    # Right answer, wrong wrapper: "base64_is_not_encryption" with no FLAG{}.
    if flag_inner(guess) == flag_inner(challenge["flag"]):
        return False, ("Right answer, wrong format — wrap it exactly as "
                       "<code>FLAG{...}</code> and submit again.")

    # A valid flag, but for a different challenge.
    other = NORM_FLAG_MAP.get(guess) or INNER_FLAG_MAP.get(flag_inner(guess))
    if other and other != challenge["id"]:
        return False, (f"That's the flag for Challenge {other:02d}, not this one. "
                       "Double-check which challenge you're on.")

    # Looks like a flag but the contents are wrong.
    if guess.startswith("flag{"):
        return False, ("Not quite — the format is right but the contents are wrong. "
                       "Re-check your decoding, then open Training Notes below.")

    return False, ("Incorrect flag. Flags look like <code>FLAG{...}</code> — "
                   "if you found the inner text, include the wrapper.")

# ── Main page template ────────────────────────────────────────────────────────
BASE_STYLE = """
/* Self-hosted so the site renders identically on a locked-down network or an
   offline lab VM, and so no student request leaves for a third party.
   JetBrains Mono, SIL Open Font License — see static/fonts/OFL.txt */
@font-face {
  font-family: 'JetBrains Mono';
  src: url('/static/fonts/JetBrainsMono-Regular.woff2') format('woff2');
  font-weight: 400;
  font-style: normal;
  font-display: swap;
}
@font-face {
  font-family: 'JetBrains Mono';
  src: url('/static/fonts/JetBrainsMono-Bold.woff2') format('woff2');
  font-weight: 700;
  font-style: normal;
  font-display: swap;
}
:root {
  --bg: #05060a;
  --surface: #0d0f18;
  --border: rgba(0,255,157,0.15);
  --neon: #00ff9d;
  --neon2: #2de2ff;
  --text: #c8d0d8;
  --dim: #7c8696;   /* 5.5:1 on --bg — WCAG AA for small text (was #5a6270, 3.3:1) */
  --red: #ff3860;
  --amber: #ffb347;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: 'JetBrains Mono', 'Fira Code', monospace;
  min-height: 100vh;
}
a { color: var(--neon); text-decoration: none; }
a:hover { text-decoration: underline; }
.btn-link {
  display: inline-block;
  padding: 0.3rem 0.8rem;
  border: 1px solid var(--neon);
  border-radius: 4px;
  color: var(--neon);
  font-size: 0.85rem;
}
.btn-link:hover { background: rgba(0,255,157,0.08); text-decoration: none; }
.block-code {
  display: block;
  background: #0a0c14;
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 0.6rem 1rem;
  color: var(--neon2);
  margin: 0.5rem 0;
}
.brand {
  display: inline-flex;
  align-items: baseline;
  gap: 0.6rem;
  text-decoration: none;
  border-radius: 4px;
  padding: 0.15rem 0.3rem;
  margin: -0.15rem -0.3rem;
}
.brand:hover { background: rgba(0,255,157,0.08); text-decoration: none; }
.brand:focus-visible { outline: 2px solid var(--neon); outline-offset: 2px; }
code {
  background: rgba(0,255,157,0.07);
  padding: 0.1rem 0.35rem;
  border-radius: 3px;
  color: var(--neon2);
  font-size: 0.9em;
}
/* Shared site header — one definition for all pages (see SITE_HEADER) */
.site-header {
  border-bottom: 1px solid var(--border);
  padding: 1rem 2rem;
  display: flex;
  align-items: center;
  gap: 1.5rem;
  background: rgba(0,255,157,0.03);
  flex-wrap: wrap;
}
.site-header .stats-chip { margin-left: auto; font-size: 0.8rem; color: var(--dim); }
.site-header .stats-chip b { color: var(--neon); }
.site-header nav { display: flex; gap: 1.2rem; align-items: center; }
.site-header nav a { font-size: 0.8rem; color: var(--dim); }
.site-header nav a:hover { color: var(--neon); }
.site-header nav a[aria-current="page"] {
  color: var(--neon);
  border-bottom: 1px solid var(--neon);
  padding-bottom: 2px;
}
.site-header nav a:focus-visible { outline: 2px solid var(--neon); outline-offset: 3px; }
.brand-mark { font-size: 1.3rem; font-weight: 700; color: var(--neon); letter-spacing: 0.05em; }
.brand-sub { color: var(--dim); font-size: 0.75rem; letter-spacing: 0.2em; }
/* Screen-reader-only text (form labels that shouldn't display) */
.visually-hidden {
  position: absolute; width: 1px; height: 1px;
  padding: 0; margin: -1px; overflow: hidden;
  clip: rect(0 0 0 0); white-space: nowrap; border: 0;
}
/* Copy-to-clipboard button on code blocks */
.copy-wrap { position: relative; }
.copy-btn {
  position: absolute; top: 0.4rem; right: 0.4rem;
  background: rgba(0,255,157,0.08);
  border: 1px solid var(--border);
  border-radius: 3px;
  color: var(--dim);
  font-family: inherit;
  font-size: 0.65rem;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  padding: 0.2rem 0.5rem;
  cursor: pointer;
}
.copy-btn:hover { color: var(--neon); border-color: var(--neon); }
.copy-btn:focus-visible { outline: 2px solid var(--neon); outline-offset: 2px; }
.copy-btn.copied { color: var(--neon); border-color: var(--neon); }
.copy-btn.copy-inline {
  position: static;
  margin-left: 0.35rem;
  vertical-align: middle;
  font-size: 0.6rem;
  padding: 0.1rem 0.35rem;
}
@media (max-width: 600px) {
  .site-header { padding: 0.8rem 1rem; gap: 0.8rem; }
  .site-header .stats-chip { margin-left: 0; order: 3; width: 100%; }
  .brand-sub { display: none; }
  .wrap { padding: 1.2rem 1rem !important; }
  .grid { padding: 1.2rem 1rem !important; }
  .hero { padding: 2rem 1rem 1.5rem !important; }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    transition: none !important;
    animation: none !important;
    scroll-behavior: auto !important;
  }
}
"""

# One header for every page. Rendered with {% include %}-style string
# substitution into each template, so a nav change is a one-line change.
# `active` is the page key ("challenges" | "docs" | "instructor"); `show_stats`
# controls the score chip. Challenge totals come from TOTAL_CHALLENGES, never
# a hardcoded 20.
SITE_HEADER = """
<header class="site-header">
  <a href="/" class="brand" title="Home" aria-label="Home"><span class="brand-mark">🛡 CYBER</span><span class="brand-sub">TRAINING ACADEMY</span></a>
  {% if show_stats %}
  <span class="stats-chip">
    Score: <b>{{ score }}</b>{% if total %} / {{ total }}{% endif %} pts
    &nbsp;|&nbsp; Solved: <b>{{ solved_count }}</b> / {{ total_challenges }}
  </span>
  {% endif %}
  <nav>
    <a href="/"{% if active == 'challenges' %} aria-current="page"{% endif %}>Challenges</a>
    <a href="/docs"{% if active == 'docs' %} aria-current="page"{% endif %}>Documents</a>
    {% if active == 'instructor' %}<a href="/instructor" aria-current="page">Instructor</a>{% endif %}
  </nav>
</header>
"""

FAVICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <rect width="64" height="64" rx="12" fill="#05060a"/>
  <path d="M32 7 54 15v16c0 13-9 22-22 26C19 53 10 44 10 31V15L32 7z"
        fill="none" stroke="#00ff9d" stroke-width="4" stroke-linejoin="round"/>
  <path d="M22 32l7 8 14-16" fill="none" stroke="#2de2ff" stroke-width="5"
        stroke-linecap="round" stroke-linejoin="round"/>
</svg>
"""

FAVICON_LINK = '<link rel="icon" type="image/svg+xml" href="/favicon.svg">'

INDEX_PAGE = """<!DOCTYPE html><html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cyber Training Academy</title>
""" + FAVICON_LINK + """
<style>
""" + BASE_STYLE + """
.hero {
  padding: 3rem 2rem 2rem;
  text-align: center;
  border-bottom: 1px solid var(--border);
  background: radial-gradient(ellipse 70% 50% at 50% 0%, rgba(0,255,157,0.06), transparent 70%);
}
.hero h1 {
  font-weight: 700;
  font-size: clamp(1.6rem, 4vw, 2.8rem);
  color: var(--neon);
  text-shadow: 0 0 30px rgba(0,255,157,0.4);
  letter-spacing: 0.05em;
  margin-bottom: 0.5rem;
}
.hero p { color: var(--dim); font-size: 0.9rem; letter-spacing: 0.1em; margin-bottom: 1.5rem; }
.progress-bar-wrap {
  max-width: 500px; margin: 0 auto 0.5rem;
  background: rgba(0,255,157,0.1); border-radius: 4px; height: 8px;
}
.progress-bar { height: 8px; background: var(--neon); border-radius: 4px; transition: width 0.5s ease; }
.stats { font-size: 0.78rem; color: var(--dim); }
.tracks {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(330px, 1fr));
  gap: 1.2rem;
  padding: 2rem;
  max-width: 1100px;
  margin: 0 auto;
}
.track {
  display: block;
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 1.4rem;
  background: var(--surface);
  color: inherit;
  text-decoration: none;
  transition: all 0.2s;
  position: relative;
}
.track:hover {
  border-color: var(--neon);
  box-shadow: 0 0 20px rgba(0,255,157,0.12);
  text-decoration: none;
}
.track:focus-visible { outline: 2px solid var(--neon); outline-offset: 3px; }
.track.done { border-color: rgba(0,255,157,0.45); background: rgba(0,255,157,0.04); }
.track-top { display: flex; align-items: baseline; gap: 0.7rem; margin-bottom: 0.5rem; }
.track-icon { font-size: 1.5rem; }
.track-name { font-size: 1.05rem; font-weight: 700; color: var(--neon); }
.track-level {
  margin-left: auto; font-size: 0.62rem; letter-spacing: 0.15em;
  text-transform: uppercase; color: var(--neon2);
  border: 1px solid rgba(45,226,255,0.3); border-radius: 3px; padding: 0.15rem 0.45rem;
}
.track-blurb { font-size: 0.83rem; line-height: 1.65; color: var(--text); margin-bottom: 1rem; }
.track-bar-wrap { background: rgba(0,255,157,0.1); border-radius: 3px; height: 6px; margin-bottom: 0.5rem; }
.track-bar { height: 6px; background: var(--neon); border-radius: 3px; transition: width 0.5s ease; }
.track-meta { display: flex; font-size: 0.72rem; color: var(--dim); gap: 0.6rem; }
.track-meta .done-tick { color: var(--neon); }
.track-meta .pts { margin-left: auto; color: var(--amber); }
</style>
</head>
<body>
<!-- FLAG{source_code_tells_all} -->
""" + SITE_HEADER + """
<div class="hero">
  <h1>Training Academy</h1>
  <p>{{ total_challenges }} CHALLENGES · {{ modules|length }} TRACKS · CYBER CTF CLUB</p>
  <div class="progress-bar-wrap"><div class="progress-bar" style="width:{{ pct }}%"></div></div>
  <div class="stats">{{ score }} / {{ total }} points &nbsp;·&nbsp; {{ solved_count }} / {{ total_challenges }} solved &nbsp;·&nbsp; {{ pct }}% complete</div>
</div>

{% if flash %}
<div style="background:rgba(0,255,157,0.08);border:1px solid var(--neon);border-radius:6px;padding:0.8rem 1.5rem;margin:1.5rem 2rem;color:var(--neon);font-size:0.9rem;">
  ✅ {{ flash }}
</div>
{% endif %}
{% if error %}
<div style="background:rgba(255,56,96,0.08);border:1px solid var(--red);border-radius:6px;padding:0.8rem 1.5rem;margin:1.5rem 2rem;color:var(--red);font-size:0.9rem;">
  ❌ {{ error }}
</div>
{% endif %}

<div class="tracks">
{% for m in modules %}
  <a class="track {% if m.solved == m.count and m.count %}done{% endif %}" href="/module/{{ m.slug }}">
    <div class="track-top">
      <span class="track-icon">{{ m.icon }}</span>
      <span class="track-name">{{ m.name }}</span>
      <span class="track-level">{{ m.level }}</span>
    </div>
    <div class="track-blurb">{{ m.blurb }}</div>
    <div class="track-bar-wrap"><div class="track-bar" style="width:{{ m.pct }}%"></div></div>
    <div class="track-meta">
      <span>{% if m.solved == m.count and m.count %}<span class="done-tick">✓ complete</span>{% else %}{{ m.solved }} / {{ m.count }} solved{% endif %}</span>
      <span class="pts">{{ m.points }} pts</span>
    </div>
  </a>
{% endfor %}
</div>
</body></html>
"""


MODULE_PAGE = """<!DOCTYPE html><html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ module.name }} · Cyber Training Academy</title>
""" + FAVICON_LINK + """
<style>
""" + BASE_STYLE + """
.hero {
  padding: 3rem 2rem 2rem;
  text-align: center;
  border-bottom: 1px solid var(--border);
  background: radial-gradient(ellipse 70% 50% at 50% 0%, rgba(0,255,157,0.06), transparent 70%);
}
.hero h1 {
  font-weight: 700;
  font-size: clamp(1.6rem, 4vw, 2.8rem);
  color: var(--neon);
  text-shadow: 0 0 30px rgba(0,255,157,0.4);
  letter-spacing: 0.05em;
  margin-bottom: 0.5rem;
}
.hero p { color: var(--dim); font-size: 0.9rem; letter-spacing: 0.1em; margin-bottom: 1.5rem; }
.progress-bar-wrap {
  max-width: 500px; margin: 0 auto 0.5rem;
  background: rgba(0,255,157,0.1); border-radius: 4px; height: 8px;
}
.progress-bar {
  height: 8px; background: var(--neon); border-radius: 4px;
  transition: width 0.5s ease;
}
.stats { font-size: 0.78rem; color: var(--dim); margin-bottom: 2rem; }
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 1rem;
  padding: 2rem;
  max-width: 1200px;
  margin: 0 auto;
}
.card {
  display: block;
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1.2rem;
  background: var(--surface);
  cursor: pointer;
  transition: all 0.2s;
  position: relative;
  color: inherit;
  text-decoration: none;
}
.card:hover {
  border-color: var(--neon);
  box-shadow: 0 0 16px rgba(0,255,157,0.12);
  text-decoration: none;
}
.card:focus-visible {
  outline: 2px solid var(--neon);
  outline-offset: 3px;
  border-color: var(--neon);
}
.card.solved { border-color: rgba(0,255,157,0.4); background: rgba(0,255,157,0.03); }
.card-num { font-size: 0.7rem; color: var(--dim); letter-spacing: 0.2em; margin-bottom: 0.4rem; }
.card-title { font-size: 0.95rem; font-weight: 700; color: var(--text); margin-bottom: 0.5rem; }
.card-meta { display: flex; gap: 0.5rem; align-items: center; font-size: 0.72rem; }
.cat-badge {
  padding: 0.15rem 0.5rem;
  border-radius: 3px;
  background: rgba(45,226,255,0.1);
  color: var(--neon2);
  border: 1px solid rgba(45,226,255,0.2);
}
.pts { color: var(--amber); margin-left: auto; }
.solved-badge {
  position: absolute; top: 0.7rem; right: 0.8rem;
  color: var(--neon); font-size: 0.8rem;
}
.cat-row {
  grid-column: 1/-1;
  font-size: 0.7rem;
  letter-spacing: 0.25em;
  color: var(--dim);
  text-transform: uppercase;
  padding: 0.5rem 0 0.2rem;
  border-top: 1px dashed var(--border);
  margin-top: 0.5rem;
}
.cat-row:first-child { border-top: none; margin-top: 0; }
.crumb { font-size: 0.78rem; margin-bottom: 0.8rem; }
.crumb a { color: var(--dim); }
.crumb a:hover { color: var(--neon); }
</style>
</head>
<body>
<!-- FLAG{source_code_tells_all} -->
""" + SITE_HEADER + """
<div class="hero">
  <div class="crumb"><a href="/">← All tracks</a></div>
  <h1>{{ module.icon }} {{ module.name }}</h1>
  <p>{{ module.blurb }}</p>
  <div class="progress-bar-wrap"><div class="progress-bar" style="width:{{ mod_pct }}%"></div></div>
  <div class="stats">{{ mod_score }} / {{ mod_points }} points &nbsp;·&nbsp; {{ mod_solved }} / {{ mod_total }} solved &nbsp;·&nbsp; {{ mod_pct }}% complete</div>
</div>

{% if flash %}
<div style="background:rgba(0,255,157,0.08);border:1px solid var(--neon);border-radius:6px;padding:0.8rem 1.5rem;margin:1.5rem 2rem;color:var(--neon);font-size:0.9rem;">
  ✅ {{ flash }}
</div>
{% endif %}
{% if error %}
<div style="background:rgba(255,56,96,0.08);border:1px solid var(--red);border-radius:6px;padding:0.8rem 1.5rem;margin:1.5rem 2rem;color:var(--red);font-size:0.9rem;">
  ❌ {{ error }}
</div>
{% endif %}

<div class="grid">
{# categories come from CATEGORY_ORDER, derived from CHALLENGES — a new category can't vanish #}
{% for cat in categories %}
  {% set cat_challenges = challenges|selectattr('category','equalto',cat)|list %}
  {% if cat_challenges %}
  <div class="cat-row">{{ cat }}</div>
  {% for c in cat_challenges %}
  <a class="card {% if c.id in solved %}solved{% endif %}" href="/challenge/{{ c.id }}">
    {% if c.id in solved %}<span class="solved-badge">✓ SOLVED</span>{% endif %}
    <div class="card-num">CHALLENGE {{ '%02d'|format(c.id) }}</div>
    <div class="card-title">{{ c.title }}</div>
    <div class="card-meta">
      <span class="cat-badge">{{ c.category }}</span>
      <span class="pts">{{ c.points }} pts</span>
    </div>
  </a>
  {% endfor %}
  {% endif %}
{% endfor %}
</div>
</body></html>
"""

CHALLENGE_PAGE = """<!DOCTYPE html><html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ c.title }} · Cyber Training Academy</title>
""" + FAVICON_LINK + """
<style>
""" + BASE_STYLE + """
.wrap { max-width: 760px; margin: 0 auto; padding: 2rem; }
.back { color: var(--dim); font-size:0.8rem; margin-bottom:1.5rem; display:block; }
.crumb { font-size:0.75rem; color:var(--dim); margin-bottom:0.9rem; }
.crumb a { color:var(--dim); }
.crumb a:hover { color:var(--neon); }
.cnum { font-size:0.72rem; letter-spacing:0.25em; color:var(--dim); margin-bottom:0.4rem; }
.ctitle { font-size:1.5rem; font-weight:700; color:var(--neon); margin-bottom:0.3rem; }
.skill-tag {
  display:inline-block; font-size:0.72rem; padding:0.15rem 0.6rem;
  border:1px solid rgba(45,226,255,0.3); border-radius:3px; color:var(--neon2);
  margin-bottom:1.2rem;
}
.story {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1.5rem;
  line-height: 1.8;
  font-size: 0.92rem;
  margin-bottom: 1.5rem;
}
.flag-form { display:flex; gap:0.8rem; align-items:center; flex-wrap:wrap; }
.flag-input {
  flex:1; min-width:240px;
  background: #0a0c14;
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 0.6rem 1rem;
  color: var(--text);
  font-family: inherit;
  font-size: 0.9rem;
}
.flag-input:focus { outline:none; border-color:var(--neon); }
.submit-btn {
  padding: 0.6rem 1.5rem;
  background: rgba(0,255,157,0.1);
  border: 1px solid var(--neon);
  border-radius: 4px;
  color: var(--neon);
  font-family: inherit;
  font-size: 0.9rem;
  cursor: pointer;
}
.submit-btn:hover { background: rgba(0,255,157,0.2); }
.solved-banner {
  background: rgba(0,255,157,0.08);
  border: 1px solid var(--neon);
  border-radius:6px; padding:1rem 1.5rem;
  color:var(--neon); margin-bottom:1rem;
  font-size:0.9rem;
}
.error-banner {
  background:rgba(255,56,96,0.08);
  border:1px solid var(--red);
  border-radius:6px; padding:0.8rem 1.2rem;
  color:var(--red); margin-bottom:1rem;
  font-size:0.9rem;
}
.nav-row { display:flex; gap:1rem; margin-top:2rem; }
.nav-btn {
  padding:0.5rem 1.2rem; border:1px solid var(--border);
  border-radius:4px; color:var(--dim); font-size:0.82rem;
}
.nav-btn:hover { border-color:var(--neon); color:var(--neon); text-decoration:none; }
.pts-badge {
  display:inline-block; font-size:0.72rem; padding:0.15rem 0.6rem;
  border:1px solid rgba(255,179,71,0.3); border-radius:3px; color:var(--amber);
  margin-left:0.5rem;
}
/* Cliff notes */
.notes-section {
  margin-top: 1.5rem;
  border: 1px solid rgba(45,226,255,0.2);
  border-radius: 8px;
  overflow: hidden;
}
.notes-toggle {
  width: 100%;
  background: rgba(45,226,255,0.05);
  border: none;
  padding: 0.9rem 1.2rem;
  text-align: left;
  color: var(--neon2);
  font-family: inherit;
  font-size: 0.88rem;
  font-weight: 700;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 0.6rem;
  letter-spacing: 0.05em;
}
.notes-toggle:hover { background: rgba(45,226,255,0.09); }
.notes-toggle .chevron { margin-left: auto; transition: transform 0.2s; font-style: normal; }
.notes-toggle.open .chevron { transform: rotate(180deg); }
.notes-body {
  display: none;
  padding: 1.2rem;
  background: rgba(13,15,24,0.6);
}
.notes-body.open { display: block; }
.note-item {
  margin-bottom: 1.2rem;
  padding-bottom: 1.2rem;
  border-bottom: 1px dashed rgba(45,226,255,0.1);
}
.note-item:last-child { margin-bottom: 0; padding-bottom: 0; border-bottom: none; }
.note-label {
  font-size: 0.78rem;
  font-weight: 700;
  color: var(--neon2);
  letter-spacing: 0.1em;
  text-transform: uppercase;
  margin-bottom: 0.4rem;
}
.note-text {
  font-size: 0.88rem;
  line-height: 1.75;
  color: var(--text);
}
/* Progressive hints */
.hints-section { margin-top: 1.5rem; }
.hints-head {
  font-size: 0.78rem; letter-spacing: 0.12em; text-transform: uppercase;
  color: var(--amber); margin-bottom: 0.6rem;
}
.hints-sub { font-size: 0.78rem; color: var(--dim); margin-bottom: 0.8rem; }
.hint {
  border: 1px solid rgba(255,179,71,0.25);
  border-radius: 6px;
  margin-bottom: 0.5rem;
  background: rgba(255,179,71,0.03);
}
.hint > summary {
  cursor: pointer;
  padding: 0.7rem 1rem;
  font-size: 0.85rem;
  color: var(--amber);
  display: flex;
  align-items: center;
  gap: 0.5rem;
  list-style: none;
}
.hint > summary::-webkit-details-marker { display: none; }
.hint > summary::after {
  content: 'reveal';
  margin-left: auto;
  font-size: 0.68rem;
  letter-spacing: 0.15em;
  text-transform: uppercase;
  color: var(--dim);
}
.hint[open] > summary::after { content: 'hide'; }
.hint > summary:hover { background: rgba(255,179,71,0.07); }
.hint > summary:focus-visible { outline: 2px solid var(--amber); outline-offset: 2px; }
.hint-tier {
  font-size: 0.68rem; letter-spacing: 0.15em; text-transform: uppercase;
  border: 1px solid rgba(255,179,71,0.3); border-radius: 3px;
  padding: 0.1rem 0.4rem; color: var(--amber);
}
.hint-body {
  padding: 0 1rem 1rem;
  font-size: 0.88rem;
  line-height: 1.75;
  color: var(--text);
}
/* Post-solve takeaway + next step */
.takeaway {
  margin-top: 0.8rem;
  padding-top: 0.8rem;
  border-top: 1px dashed rgba(0,255,157,0.25);
  color: var(--text);
  font-size: 0.88rem;
  line-height: 1.7;
}
.takeaway b { color: var(--neon); }
.next-cta {
  display: inline-block;
  margin-top: 1rem;
  padding: 0.6rem 1.4rem;
  background: rgba(0,255,157,0.12);
  border: 1px solid var(--neon);
  border-radius: 4px;
  color: var(--neon);
  font-size: 0.9rem;
  font-weight: 700;
}
.next-cta:hover { background: rgba(0,255,157,0.22); text-decoration: none; }
.next-cta:focus-visible { outline: 2px solid var(--neon); outline-offset: 3px; }
/* Further reading */
.reading { margin-top: 1.5rem; font-size: 0.82rem; color: var(--dim); }
.reading-head {
  font-size: 0.72rem; letter-spacing: 0.15em; text-transform: uppercase;
  color: var(--neon2); margin-bottom: 0.5rem;
}
.reading a { color: var(--neon2); }
.reading li { margin-bottom: 0.25rem; list-style: none; }
.reading li::before { content: '📄 '; }
@media (prefers-reduced-motion: reduce) {
  * { transition: none !important; animation: none !important; }
}
</style>
</head>
<body>
""" + SITE_HEADER + """
<div class="wrap">
  <div class="crumb">
    <a href="/">All tracks</a> &nbsp;/&nbsp; <a href="/module/{{ module.slug }}">{{ module.icon }} {{ module.name }}</a>
  </div>
  <div class="cnum">CHALLENGE {{ '%02d'|format(c.id) }} &nbsp;·&nbsp; {{ pos }} of {{ mod_count }} in this track</div>
  <div class="ctitle">{{ c.title }} <span class="pts-badge">{{ c.points }} pts</span></div>
  <div class="skill-tag">🎓 Skill: {{ c.skill }}</div>

  {% if solved %}
  <div class="solved-banner">
    ✅ <b>CHALLENGE SOLVED!</b> +{{ c.points }} points
    {% if c.takeaway %}
    <div class="takeaway"><b>What this means:</b> {{ c.takeaway }}</div>
    {% endif %}
    {% if next_id %}
    <a class="next-cta" href="/challenge/{{ next_id }}">Next: Challenge {{ '%02d'|format(next_id) }} →</a>
    {% else %}
    <a class="next-cta" href="/module/{{ module.slug }}">🏁 {{ module.name }} complete — back to the track</a>
    {% endif %}
  </div>
  {% endif %}
  {% if error %}
  <div class="error-banner">❌ {{ error|safe }}</div>
  {% endif %}

  <div class="story">{{ c.story|safe }}</div>

  <form class="flag-form" method="POST">
    <label class="visually-hidden" for="flag-input">Flag for challenge {{ c.id }}, in the form FLAG&#123;...&#125;</label>
    <input class="flag-input" id="flag-input" name="flag" placeholder="FLAG{...}"
           autocomplete="off" autocapitalize="off" spellcheck="false"
           {% if solved %}disabled{% endif %}>
    <button class="submit-btn" type="submit" {% if solved %}disabled{% endif %}>Submit Flag</button>
  </form>

  {% if c.hints and not solved %}
  <div class="hints-section">
    <div class="hints-head">💡 Stuck? Hints</div>
    <div class="hints-sub">Open them one at a time — try the nudge before the answer. You learn it by finding it.</div>
    {% for label, text in c.hints %}
    <details class="hint">
      <summary><span class="hint-tier">{{ loop.index }}</span> {{ label }}</summary>
      <div class="hint-body">{{ text|safe }}</div>
    </details>
    {% endfor %}
  </div>
  {% endif %}

  {% if c.docs %}
  <div class="reading">
    <div class="reading-head">Further reading</div>
    <ul>
      {% for d in c.docs %}
      <li><a href="/docs/{{ d|urlencode }}" target="_blank" rel="noopener">{{ d.rsplit('.', 1)[0].replace('_', ' ') }}</a></li>
      {% endfor %}
    </ul>
  </div>
  {% endif %}

  {% if c.notes %}
  <div class="notes-section">
    <button class="notes-toggle {% if solved %}open{% endif %}" onclick="toggleNotes(this)"
            aria-expanded="{{ 'true' if solved else 'false' }}" aria-controls="notes-body">
      📖 &nbsp;Training Notes — Key Concepts for This Challenge
      <i class="chevron">▼</i>
    </button>
    <div class="notes-body {% if solved %}open{% endif %}" id="notes-body">
      {% for label, text in c.notes %}
      <div class="note-item">
        <div class="note-label">{{ label }}</div>
        <div class="note-text">{{ text|safe }}</div>
      </div>
      {% endfor %}
    </div>
  </div>
  {% endif %}

  <div class="nav-row">
    {% if prev_id %}
    <a href="/challenge/{{ prev_id }}" class="nav-btn">← Challenge {{ '%02d'|format(prev_id) }}</a>
    {% endif %}
    <a href="/module/{{ module.slug }}" class="nav-btn" style="margin-left:auto;">{{ module.icon }} {{ module.name }}</a>
    {% if next_id %}
    <a href="/challenge/{{ next_id }}" class="nav-btn">Challenge {{ '%02d'|format(next_id) }} →</a>
    {% endif %}
  </div>
</div>
<script>
// Add a copy button to every code block and inline <code> long enough to be
// worth copying. Progressive enhancement: without JS the page is unchanged.
(function addCopyButtons() {
  const targets = Array.from(document.querySelectorAll('.block-code'));
  document.querySelectorAll('.story code, .hint-body code, .note-text code').forEach(el => {
    if (el.textContent.trim().length >= 12) targets.push(el);
  });
  targets.forEach(el => {
    if (el.dataset.copyReady) return;
    el.dataset.copyReady = '1';
    const isBlock = el.classList.contains('block-code');
    const copyText = el.textContent.trim();
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'copy-btn';
    btn.textContent = 'copy';
    btn.setAttribute('aria-label', 'Copy to clipboard');
    btn.addEventListener('click', async (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      try {
        await navigator.clipboard.writeText(copyText);
      } catch (err) {
        const ta = document.createElement('textarea');
        ta.value = copyText;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        ta.remove();
      }
      btn.textContent = 'copied';
      btn.classList.add('copied');
      setTimeout(() => { btn.textContent = 'copy'; btn.classList.remove('copied'); }, 1500);
    });
    if (isBlock) {
      const wrap = document.createElement('div');
      wrap.className = 'copy-wrap';
      el.parentNode.insertBefore(wrap, el);
      wrap.appendChild(el);
      wrap.appendChild(btn);
    } else {
      btn.classList.add('copy-inline');
      el.insertAdjacentElement('afterend', btn);
    }
  });
})();

function toggleNotes(btn) {
  const body = document.getElementById('notes-body');
  const isOpen = body.classList.contains('open');
  body.classList.toggle('open', !isOpen);
  btn.classList.toggle('open', !isOpen);
  btn.setAttribute('aria-expanded', String(!isOpen));
}
</script>
</body></html>
"""

DOCS_PAGE = """<!DOCTYPE html><html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Documents · Cyber Training Academy</title>
""" + FAVICON_LINK + """
<style>
""" + BASE_STYLE + """
.wrap { max-width: 760px; margin: 0 auto; padding: 2rem; }
.page-title { font-size:1.5rem; font-weight:700; color:var(--neon); margin-bottom:0.3rem; }
.page-sub { color:var(--dim); font-size:0.85rem; margin-bottom:1.5rem; }
.doc-row {
  display:flex; align-items:center; gap:1rem;
  background:var(--surface); border:1px solid var(--border); border-radius:6px;
  padding:0.8rem 1rem; margin-bottom:0.6rem;
}
.doc-name { color:var(--text); flex:1; }
.doc-ext { color:var(--dim); font-size:0.72rem; letter-spacing:0.15em; }
.empty { color:var(--dim); font-size:0.85rem; }
</style>
</head>
<body>
""" + SITE_HEADER + """
<div class="wrap">
  <div class="page-title">Documents</div>
  <div class="page-sub">One-pagers and reference material for the club.</div>
  {% for d in docs %}
  <div class="doc-row">
    <span class="doc-name">{{ d.title }}</span>
    <span class="doc-ext">{{ d.ext }}</span>
    <a class="btn-link" href="/docs/{{ d.filename|urlencode }}" target="_blank">Open</a>
  </div>
  {% else %}
  <p class="empty">No documents yet.</p>
  {% endfor %}
</div>
</body></html>
"""

SPLASH_PAGE = """<!DOCTYPE html><html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hold On \u00b7 Cyber Training Academy</title>
""" + FAVICON_LINK + """
<style>
""" + BASE_STYLE + """
.gate { max-width: 720px; margin: 0 auto; padding: 3rem 2rem 4rem; }
.tag {
  display:inline-block; font-size:0.7rem; letter-spacing:0.25em; color:var(--amber);
  border:1px solid rgba(255,179,71,0.4); border-radius:3px; padding:0.25rem 0.6rem; margin-bottom:1.5rem;
}
.gate h1 { font-size:1.9rem; line-height:1.25; color:var(--amber); margin-bottom:1.2rem; }
.gate p { line-height:1.7; margin-bottom:1.1rem; font-size:0.95rem; }
.gate strong { color:var(--text); }
.urlbar {
  background:#0a0c14; border:1px solid var(--border); border-radius:6px;
  padding:0.9rem 1rem; margin:1.5rem 0; font-size:0.9rem; color:var(--dim);
  overflow-wrap:anywhere;
}
.urlbar b { color:var(--red); }
.checklist {
  background:var(--surface); border:1px solid var(--border); border-left:3px solid var(--neon);
  border-radius:6px; padding:1.2rem 1.4rem; margin:1.8rem 0;
}
.checklist h2 { font-size:0.75rem; letter-spacing:0.2em; color:var(--neon); margin-bottom:0.9rem; }
.checklist li { list-style:none; margin-bottom:0.7rem; font-size:0.88rem; line-height:1.55; padding-left:1.6rem; position:relative; }
.checklist li:last-child { margin-bottom:0; }
.checklist li:before { content:"\u2713"; position:absolute; left:0; color:var(--neon); }
.warnbox {
  background:rgba(255,56,96,0.06); border:1px solid rgba(255,56,96,0.3);
  border-radius:6px; padding:1.1rem 1.3rem; margin:1.8rem 0; font-size:0.88rem; line-height:1.6;
}
.warnbox h2 { font-size:0.75rem; letter-spacing:0.2em; color:var(--red); margin-bottom:0.7rem; }
.enter-btn {
  font-family:inherit; font-size:0.95rem; font-weight:700; cursor:pointer;
  background:transparent; border:1px solid var(--neon); color:var(--neon);
  border-radius:4px; padding:0.8rem 1.4rem; margin-top:0.5rem;
}
.enter-btn:hover { background:rgba(0,255,157,0.1); }
.kicker { color:var(--dim); font-size:0.78rem; line-height:1.6; margin-top:1.5rem; }
</style>
</head>
<body>
<div class="gate">
  <div class="tag">\u26a0 STOP \u00b7 READ \u00b7 THEN PROCEED</div>
  <h1>You just clicked a link to a site called<br>&ldquo;should I click this link?&rdquo;</h1>

  <p>And you clicked it. Immediately. Without checking.</p>

  <p><strong>Good news:</strong> you're in the right place \u2014 this really is the Cyber
  Training Academy range. <strong>Bad news:</strong> you didn't know that when you clicked.
  That's the whole lesson, and you just lived it.</p>

  <div class="urlbar">
    Look at what you actually loaded:<br><br>
    https://ctf.<b>shouldiclickthislink.com</b>/
  </div>

  <p>If a domain has to <em>ask</em> whether you should trust it, that is not a
  recommendation. Real attackers won't be this honest with you.</p>

  <div class="checklist">
    <h2>BEFORE YOU CLICK \u2014 EVERY TIME</h2>
    <ul>
      <li>Hover first and read the <strong>real</strong> destination. Link text lies; the URL doesn't.</li>
      <li>Read the domain <strong>right to left</strong>. In <code>login.microsoft.evil.com</code>, the owner is <code>evil.com</code>.</li>
      <li>Watch for lookalikes: <code>rn</code> vs <code>m</code>, <code>0</code> vs <code>O</code>, extra hyphens, bonus subdomains.</li>
      <li>Unexpected attachment, urgent tone, or a request for credentials? Treat it as hostile until proven otherwise.</li>
      <li>Anything touching money, passwords, or MFA: <strong>verify out-of-band</strong>. Phone the person. Don't reply to the email.</li>
      <li>Not sure? <strong>Don't click \u2014 report it.</strong> Nobody has ever been fired for reporting a phish.</li>
    </ul>
  </div>

  <div class="warnbox">
    <h2>ABOUT THIS TRAINING RANGE</h2>
    Everything past this point is <strong>deliberately broken on purpose</strong> \u2014 weak
    cookies, default passwords, SQL injection, command injection, secrets sitting in plain
    sight. It is a lab. Nothing here reflects how a healthy production site behaves, and
    none of these techniques belong on a system you don't have written permission to test.
  </div>

  <p>Now go break it \u2014 on purpose, in here, where it's allowed.</p>

  <form method="post" action="/welcome">
    <button class="enter-btn" type="submit">I read it. I verified the domain. Let me in \u2192</button>
  </form>

  <p class="kicker">
    This page exists because the fastest way to un-train a user is to reward them for
    clicking. If this link had been real, the right move was to close the tab.
  </p>
</div>
</body></html>
"""

INSTRUCTOR_PAGE = """<!DOCTYPE html><html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Instructor View · Cyber Training Academy</title>
""" + FAVICON_LINK + """
<style>
""" + BASE_STYLE + """
.wrap { max-width: 960px; margin: 0 auto; padding: 2rem; }
.page-title { font-size:1.5rem; font-weight:700; color:var(--neon); margin-bottom:0.3rem; }
.page-sub { color:var(--dim); font-size:0.85rem; margin-bottom:1.5rem; line-height:1.7; }
.tiles { display:flex; gap:1rem; flex-wrap:wrap; margin-bottom:1.8rem; }
.tile {
  background:var(--surface); border:1px solid var(--border);
  border-radius:8px; padding:1rem 1.3rem; min-width:150px;
}
.tile-num { font-size:1.6rem; font-weight:700; color:var(--neon); }
.tile-lbl { font-size:0.7rem; letter-spacing:0.15em; text-transform:uppercase; color:var(--dim); }
table { width:100%; border-collapse:collapse; font-size:0.82rem; }
th {
  text-align:left; padding:0.6rem 0.7rem; color:var(--dim);
  font-size:0.68rem; letter-spacing:0.15em; text-transform:uppercase;
  border-bottom:1px solid var(--border); font-weight:400;
}
td { padding:0.6rem 0.7rem; border-bottom:1px solid rgba(0,255,157,0.06); }
tr:hover td { background:rgba(0,255,157,0.03); }
.c-id { color:var(--dim); }
.c-title { color:var(--text); }
.bar-wrap { background:rgba(255,56,96,0.12); border-radius:3px; height:6px; min-width:60px; }
.bar { height:6px; border-radius:3px; background:var(--red); }
.num { text-align:right; font-variant-numeric:tabular-nums; }
.hot { color:var(--red); font-weight:700; }
.empty { color:var(--dim); font-size:0.85rem; padding:2rem 0; }
.privacy {
  margin-top:2rem; padding:1rem 1.2rem; font-size:0.78rem; line-height:1.7;
  color:var(--dim); border:1px dashed var(--border); border-radius:6px;
}
</style>
</head>
<body>
""" + SITE_HEADER + """
<div class="wrap">
  <div class="page-title">Instructor View</div>
  <div class="page-sub">
    Which challenge is burning the room. Sorted by failed attempts per solve, hardest first.
  </div>

  <div class="tiles">
    <div class="tile"><div class="tile-num">{{ sessions }}</div><div class="tile-lbl">Sessions started</div></div>
    <div class="tile"><div class="tile-num">{{ total_attempts }}</div><div class="tile-lbl">Flag attempts</div></div>
    <div class="tile"><div class="tile-num">{{ total_solves }}</div><div class="tile-lbl">Solves</div></div>
    <div class="tile"><div class="tile-num">{{ overall_rate }}%</div><div class="tile-lbl">Success rate</div></div>
  </div>

  {% if total_attempts %}
  <table>
    <thead>
      <tr>
        <th>#</th><th>Challenge</th><th>Category</th>
        <th class="num">Attempts</th><th class="num">Solves</th>
        <th class="num">Failed</th><th class="num">Fails / solve</th><th>Friction</th>
      </tr>
    </thead>
    <tbody>
    {% for r in rows %}
      <tr>
        <td class="c-id">{{ '%02d'|format(r.id) }}</td>
        <td class="c-title">{{ r.title }}</td>
        <td style="color:var(--neon2)">{{ r.category }}</td>
        <td class="num">{{ r.attempts }}</td>
        <td class="num">{{ r.solves }}</td>
        <td class="num">{{ r.failures }}</td>
        <td class="num {% if r.friction >= 2 %}hot{% endif %}">{{ r.friction }}</td>
        <td>
          {% if max_friction %}
          <div class="bar-wrap"><div class="bar" style="width:{{ (r.friction / max_friction * 100)|round|int }}%"></div></div>
          {% endif %}
        </td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p class="empty">No attempts recorded yet. Numbers appear as students submit flags.</p>
  {% endif %}

  <div class="privacy">
    <b>What this does and doesn't collect.</b> Counters are aggregate and anonymous
    &mdash; attempts and solves per challenge, plus how many sessions started. No
    identities, no submitted values, nothing written to disk. Everything lives in
    process memory and resets when the container restarts, so these numbers cover
    the current meeting only.
  </div>
</div>
</body></html>
"""


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/welcome", methods=["GET", "POST"])
def welcome():
    """Phishing-awareness splash. POST (a button, not a link) acknowledges it."""
    if request.method == "POST":
        if not session.get("warned"):
            record_session()
        session["warned"] = True
        return redirect(url_for("index"))
    return render_template_string(SPLASH_PAGE, **header_ctx("challenges", show_stats=False))


@app.route("/")
def index():
    if not session.get("warned"):
        return redirect(url_for("welcome"))
    solved = get_solved()
    score = get_score()
    pct = round(score / TOTAL_POINTS * 100)
    flash = request.args.get("flash", "")
    error = request.args.get("error", "")
    return render_template_string(INDEX_PAGE,
        modules=module_progress(), pct=pct,
        flash=flash, error=error, **header_ctx("challenges"))


@app.route("/module/<slug>")
def module(slug):
    if not session.get("warned"):
        return redirect(url_for("welcome"))
    m = MODULE_BY_SLUG.get(slug)
    if not m:
        return redirect(url_for("index"))
    solved = get_solved()
    chs = module_challenges(slug)
    pts = sum(c["points"] for c in chs)
    earned = sum(c["points"] for c in chs if c["id"] in solved)
    # Categories in this track only, in first-appearance order.
    cats = list(dict.fromkeys(c["category"] for c in chs))
    return render_template_string(MODULE_PAGE,
        module=m, challenges=chs, solved=solved, categories=cats,
        mod_score=earned, mod_points=pts,
        mod_solved=sum(1 for c in chs if c["id"] in solved), mod_total=len(chs),
        mod_pct=round(earned / pts * 100) if pts else 0,
        flash=request.args.get("flash", ""), error=request.args.get("error", ""),
        **header_ctx("challenges"))


@app.route("/challenge/<int:cid>", methods=["GET", "POST"])
def challenge(cid):
    c = next((x for x in CHALLENGES if x["id"] == cid), None)
    if not c:
        return "Challenge not found", 404
    solved_ids = get_solved()
    already_solved = cid in solved_ids
    error = ""
    if request.method == "POST":
        submitted = request.form.get("flag", "")
        is_correct, message = grade_submission(submitted, c)
        # Count the attempt only if this is a genuine try, not a re-submit of an
        # already-solved challenge, and skip empty submissions.
        if not already_solved and normalize_flag(submitted):
            record_attempt(cid, is_correct)
        if is_correct:
            mark_solved(c["flag"])
            already_solved = True
        else:
            error = message
    prev_id, next_id, pos, mod_count = module_neighbours(c)
    return render_template_string(CHALLENGE_PAGE,
        c=c, solved=already_solved, error=error,
        module=MODULE_BY_SLUG.get(c["module"], MODULES[0]),
        prev_id=prev_id, next_id=next_id, pos=pos, mod_count=mod_count,
        **header_ctx("challenges"))


@app.route("/instructor")
def instructor():
    """Anonymous aggregate view: which challenge is burning the room.

    Deliberately NOT token-gated — the whole site sits behind one shared
    nginx basic-auth password, and the data here is anonymous aggregate with
    nothing per-student in it, so students seeing "19 is hard for everyone"
    is harmless (arguably reassuring).
    """
    rows = stats_rows()
    total_attempts = sum(r["attempts"] for r in rows)
    total_solves = sum(r["solves"] for r in rows)
    return render_template_string(
        INSTRUCTOR_PAGE,
        rows=rows,
        sessions=SESSION_COUNT["total"],
        total_attempts=total_attempts,
        total_solves=total_solves,
        overall_rate=round(total_solves / total_attempts * 100) if total_attempts else 0,
        max_friction=max((r["friction"] for r in rows), default=0) or 0,
        **header_ctx("instructor"),
    )


# ── Favicon ───────────────────────────────────────────────────────────
@app.route("/favicon.svg")
def favicon_svg():
    return Response(FAVICON_SVG, mimetype="image/svg+xml",
                    headers={"Cache-Control": "public, max-age=86400"})


@app.route("/favicon.ico")
def favicon_ico():
    # Browsers request /favicon.ico for pages without an explicit <link>.
    return redirect(url_for("favicon_svg"))


# ── File downloads ────────────────────────────────────────────────────────────
@app.route("/files/<path:filename>")
def files(filename):
    return send_from_directory(FILES_DIR, filename)


# ── Documents ─────────────────────────────────────────────────────────────────
@app.route("/docs")
def docs():
    names = sorted(os.listdir(DOCS_DIR)) if os.path.isdir(DOCS_DIR) else []
    entries = []
    for name in names:
        if name.startswith(".") or not os.path.isfile(os.path.join(DOCS_DIR, name)):
            continue
        stem, ext = os.path.splitext(name)
        entries.append({"filename": name,
                        "title": stem.replace("_", " ").replace("-", " "),
                        "ext": ext.lstrip(".").upper()})
    return render_template_string(DOCS_PAGE, docs=entries, **header_ctx("docs"))


@app.route("/docs/<path:filename>")
def doc_file(filename):
    return send_from_directory(DOCS_DIR, filename)


# ── Challenge 5: header endpoint ──────────────────────────────────────────────
@app.route("/header-challenge")
def header_challenge():
    r = Response(
        "<h2 style='font-family:monospace;color:#00ff9d;'>Check the response headers on this request!</h2>"
        "<p style='font-family:monospace;color:#888;'>Use curl -I or browser DevTools → Network → Headers</p>",
        content_type="text/html"
    )
    r.headers["X-Flag"] = "FLAG{http_headers_talk_too_much}"
    r.headers["X-Hint"] = "You found the right header!"
    return r


# ── Challenge 10: cookie auth ─────────────────────────────────────────────────
@app.route("/cookie-challenge")
def cookie_challenge():
    role = request.cookies.get("role", "guest")
    if role == "admin":
        body = f"<h2>Welcome, Admin!</h2><p>Flag: <code>FLAG{{cookies_are_not_auth}}</code></p>"
    else:
        body = "<h2>Welcome, guest.</h2><p>You don't have access to the admin area.</p><p>Hint: Try changing your <code>role</code> cookie to <code>admin</code>.</p>"
    resp = Response(f"""<!DOCTYPE html><html><head>
    <link href='/static/fonts.css' rel='stylesheet'>
    <style>body{{background:#05060a;color:#c8d0d8;font-family:'JetBrains Mono',monospace;padding:2rem;}}
    code{{background:rgba(0,255,157,0.1);padding:0.2rem 0.4rem;border-radius:3px;color:#2de2ff;}}
    h2{{color:#00ff9d;}}</style></head><body>{body}
    <p style='margin-top:1rem'><a href='/' style='color:#5a6270;font-size:0.85rem;'>← Back to challenges</a></p>
    </body></html>""", content_type="text/html")
    if not request.cookies.get("role"):
        resp.set_cookie("role", "guest")
    return resp


# ── Challenge 11: URL param ───────────────────────────────────────────────────
@app.route("/param-challenge")
def param_challenge():
    user = request.args.get("user", "guest")
    if user == "admin":
        msg = f"<h2>Admin Panel</h2><p>Flag: <code>FLAG{{url_params_are_not_access_control}}</code></p>"
    else:
        msg = f"<h2>Hello, {user}!</h2><p>You're logged in as <b>{user}</b>. Only admins can see the flag.</p>"
    return f"""<!DOCTYPE html><html><head>
    <link href='/static/fonts.css' rel='stylesheet'>
    <style>body{{background:#05060a;color:#c8d0d8;font-family:'JetBrains Mono',monospace;padding:2rem;}}
    code{{background:rgba(0,255,157,0.1);padding:0.2rem 0.4rem;border-radius:3px;color:#2de2ff;}}
    h2{{color:#00ff9d;}}</style></head><body>{msg}
    <p style='margin-top:1rem'><a href='/' style='color:#5a6270;font-size:0.85rem;'>← Back</a></p>
    </body></html>"""


# ── Challenge 12: robots.txt ──────────────────────────────────────────────────
@app.route("/robots.txt")
def robots():
    return Response(
        "User-agent: *\nDisallow: /secret-training-vault\nDisallow: /admin-notes.txt\n",
        content_type="text/plain"
    )

@app.route("/secret-training-vault")
def secret_vault():
    return """<!DOCTYPE html><html><head>
    <link href='/static/fonts.css' rel='stylesheet'>
    <style>body{background:#05060a;color:#c8d0d8;font-family:'JetBrains Mono',monospace;padding:2rem;}
    code{background:rgba(0,255,157,0.1);padding:0.2rem 0.4rem;border-radius:3px;color:#2de2ff;}
    h2{color:#00ff9d;}</style></head><body>
    <h2>🔒 Secret Training Vault</h2>
    <p>You found it by reading robots.txt!</p>
    <p>Flag: <code>FLAG{robots_txt_is_not_a_lock}</code></p>
    <p style='margin-top:1rem'><a href='/' style='color:#5a6270;font-size:0.85rem;'>← Back</a></p>
    </body></html>"""


# ── Challenge 13: hidden path ─────────────────────────────────────────────────
@app.route("/backup")
def backup():
    return """<!DOCTYPE html><html><head>
    <link href='/static/fonts.css' rel='stylesheet'>
    <style>body{background:#05060a;color:#c8d0d8;font-family:'JetBrains Mono',monospace;padding:2rem;}
    code{background:rgba(0,255,157,0.1);padding:0.2rem 0.4rem;border-radius:3px;color:#2de2ff;}
    h2{color:#00ff9d;}</style></head><body>
    <h2>📁 Backup Directory</h2>
    <p>You found the backup endpoint! Good instincts.</p>
    <p>Flag: <code>FLAG{hidden_paths_hide_in_plain_sight}</code></p>
    <p style='margin-top:1rem'><a href='/' style='color:#5a6270;font-size:0.85rem;'>← Back</a></p>
    </body></html>"""


# ── Challenge 16: default creds ───────────────────────────────────────────────
@app.route("/default-login", methods=["GET", "POST"])
def default_login():
    msg = ""
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        if u == "admin" and p == "admin":
            msg = f'<p style="color:#00ff9d">✅ Logged in! Flag: <code>FLAG{{change_your_default_creds}}</code></p>'
        else:
            msg = '<p style="color:#ff3860">❌ Invalid credentials. Try common defaults.</p>'
    return f"""<!DOCTYPE html><html><head>
    <link href='/static/fonts.css' rel='stylesheet'>
    <style>body{{background:#05060a;color:#c8d0d8;font-family:'JetBrains Mono',monospace;padding:2rem;max-width:400px;margin:3rem auto;}}
    input{{background:#0d0f18;border:1px solid rgba(0,255,157,0.2);border-radius:4px;padding:0.6rem;color:#c8d0d8;font-family:inherit;width:100%;margin-bottom:0.8rem;}}
    button{{background:rgba(0,255,157,0.1);border:1px solid #00ff9d;border-radius:4px;padding:0.6rem 1.5rem;color:#00ff9d;font-family:inherit;cursor:pointer;}}
    h2{{color:#00ff9d;margin-bottom:1.5rem;}}
    code{{background:rgba(0,255,157,0.1);padding:0.2rem 0.4rem;border-radius:3px;color:#2de2ff;}}</style></head><body>
    <h2>🔐 Admin Login</h2>
    {msg}
    <form method='POST'>
      <input name='username' placeholder='Username'><br>
      <input name='password' type='password' placeholder='Password'><br>
      <button type='submit'>Login</button>
    </form>
    <p style='margin-top:1rem'><a href='/' style='color:#5a6270;font-size:0.85rem;'>← Back</a></p>
    </body></html>"""


# ── Challenge 17: weak token ──────────────────────────────────────────────────
@app.route("/token-challenge")
def token_challenge():
    token = request.args.get("token", "")
    if token:
        try:
            decoded = base64.b64decode(token).decode()
            if decoded == "admin":
                return f"""<!DOCTYPE html><html><head>
                <link href='/static/fonts.css' rel='stylesheet'>
                <style>body{{background:#05060a;color:#c8d0d8;font-family:'JetBrains Mono',monospace;padding:2rem;}}
                code{{background:rgba(0,255,157,0.1);padding:0.2rem 0.4rem;border-radius:3px;color:#2de2ff;}}
                h2{{color:#00ff9d;}}</style></head><body>
                <h2>✅ Admin Access Granted!</h2>
                <p>Flag: <code>FLAG{{weak_tokens_are_predictable}}</code></p>
                <p style='margin-top:1rem'><a href='/' style='color:#5a6270;font-size:0.85rem;'>← Back</a></p>
                </body></html>"""
        except Exception:
            pass
    guest_token = base64.b64encode(b"guest").decode()
    return f"""<!DOCTYPE html><html><head>
    <link href='/static/fonts.css' rel='stylesheet'>
    <style>body{{background:#05060a;color:#c8d0d8;font-family:'JetBrains Mono',monospace;padding:2rem;}}
    code{{background:rgba(0,255,157,0.1);padding:0.2rem 0.4rem;border-radius:3px;color:#2de2ff;}}
    h2{{color:#00ff9d;}}</style></head><body>
    <h2>🎫 Token Authentication</h2>
    <p>Your guest token: <code>{guest_token}</code></p>
    <p>Append it to the URL: <code>?token={guest_token}</code></p>
    <p style='margin-top:0.8rem;color:#5a6270;'>Hint: What if you replaced "guest" with "admin" before encoding?</p>
    <p style='margin-top:1rem'><a href='/' style='color:#5a6270;font-size:0.85rem;'>← Back</a></p>
    </body></html>"""


# ── Challenge 18: command injection ──────────────────────────────────────────
@app.route("/ping-tool", methods=["GET", "POST"])
def ping_tool():
    output = ""
    if request.method == "POST":
        host = request.form.get("host", "")
        # Intentionally vulnerable - no sanitisation
        try:
            result = subprocess.run(
                f"ping -c 1 {host} 2>&1 || true",
                shell=True, capture_output=True, text=True, timeout=5
            )
            output = result.stdout + result.stderr
        except Exception as e:
            output = str(e)
    return f"""<!DOCTYPE html><html><head>
    <link href='/static/fonts.css' rel='stylesheet'>
    <style>body{{background:#05060a;color:#c8d0d8;font-family:'JetBrains Mono',monospace;padding:2rem;max-width:600px;margin:2rem auto;}}
    input{{background:#0d0f18;border:1px solid rgba(0,255,157,0.2);border-radius:4px;padding:0.6rem;color:#c8d0d8;font-family:inherit;width:70%;}}
    button{{background:rgba(0,255,157,0.1);border:1px solid #00ff9d;border-radius:4px;padding:0.6rem 1.2rem;color:#00ff9d;font-family:inherit;cursor:pointer;margin-left:0.5rem;}}
    pre{{background:#0a0c14;border:1px solid rgba(0,255,157,0.15);border-radius:4px;padding:1rem;color:#2de2ff;white-space:pre-wrap;word-break:break-all;margin-top:1rem;font-size:0.85rem;max-height:300px;overflow-y:auto;}}
    h2{{color:#00ff9d;margin-bottom:1.2rem;}}</style></head><body>
    <h2>🏓 Network Ping Tool</h2>
    <form method='POST'>
      <input name='host' placeholder='hostname or IP' value=''>
      <button type='submit'>Ping</button>
    </form>
    {'<pre>' + output + '</pre>' if output else ''}
    <p style='margin-top:1rem'><a href='/' style='color:#5a6270;font-size:0.85rem;'>← Back</a></p>
    </body></html>"""


# ── Challenge 19: SQL injection ───────────────────────────────────────────────
@app.route("/sqli-login", methods=["GET", "POST"])
def sqli_login():
    msg = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        try:
            conn = sqlite3.connect("/tmp/users.db")
            # Intentionally vulnerable query
            query = f"SELECT flag FROM users WHERE username='{username}' AND password='{password}'"
            cur = conn.execute(query)
            row = cur.fetchone()
            conn.close()
            if row:
                msg = f'<p style="color:#00ff9d">✅ Logged in! Flag: <code>{row[0]}</code></p>'
            else:
                msg = '<p style="color:#ff3860">❌ Invalid credentials.</p>'
        except Exception as e:
            msg = f'<p style="color:#ff3860">SQL Error: {e}</p>'
    return f"""<!DOCTYPE html><html><head>
    <link href='/static/fonts.css' rel='stylesheet'>
    <style>body{{background:#05060a;color:#c8d0d8;font-family:'JetBrains Mono',monospace;padding:2rem;max-width:400px;margin:3rem auto;}}
    input{{background:#0d0f18;border:1px solid rgba(0,255,157,0.2);border-radius:4px;padding:0.6rem;color:#c8d0d8;font-family:inherit;width:100%;margin-bottom:0.8rem;}}
    button{{background:rgba(0,255,157,0.1);border:1px solid #00ff9d;border-radius:4px;padding:0.6rem 1.5rem;color:#00ff9d;font-family:inherit;cursor:pointer;}}
    code{{background:rgba(0,255,157,0.1);padding:0.2rem 0.4rem;border-radius:3px;color:#2de2ff;}}
    h2{{color:#00ff9d;margin-bottom:1.5rem;}}</style></head><body>
    <h2>🗄 Member Login</h2>
    {msg}
    <form method='POST'>
      <input name='username' placeholder='Username'><br>
      <input name='password' type='password' placeholder='Password'><br>
      <button type='submit'>Login</button>
    </form>
    <p style='margin-top:1rem'><a href='/' style='color:#5a6270;font-size:0.85rem;'>← Back</a></p>
    </body></html>"""


# ── Challenge 20: final boss chain ────────────────────────────────────────────
@app.route("/final/robots.txt")
def final_robots():
    return Response(
        "User-agent: *\nDisallow: /final/decode-me\n",
        content_type="text/plain"
    )

@app.route("/final/decode-me")
def final_decode():
    # Base64 of "/final/vault?key=banshee"
    encoded = base64.b64encode(b"/final/vault?key=banshee").decode()
    return f"""<!DOCTYPE html><html><head>
    <link href='/static/fonts.css' rel='stylesheet'>
    <style>body{{background:#05060a;color:#c8d0d8;font-family:'JetBrains Mono',monospace;padding:2rem;}}
    code{{background:rgba(0,255,157,0.1);padding:0.2rem 0.4rem;border-radius:3px;color:#2de2ff;}}
    h2{{color:#00ff9d;}}</style></head><body>
    <h2>📡 Encoded Transmission</h2>
    <p>Decode this Base64 string to find your next destination:</p>
    <p><code>{encoded}</code></p>
    <p style='margin-top:1rem'><a href='/' style='color:#5a6270;font-size:0.85rem;'>← Back</a></p>
    </body></html>"""

@app.route("/final/vault")
def final_vault():
    key = request.args.get("key", "")
    if key == "banshee":
        return f"""<!DOCTYPE html><html><head>
        <link href='/static/fonts.css' rel='stylesheet'>
        <style>body{{background:#05060a;color:#c8d0d8;font-family:'JetBrains Mono',monospace;padding:2rem;}}
        code{{background:rgba(0,255,157,0.1);padding:0.2rem 0.4rem;border-radius:3px;color:#2de2ff;}}
        h2{{color:#00ff9d;}}</style></head><body>
        <h2>🏆 FINAL VAULT UNLOCKED</h2>
        <p>You chained robots.txt → Base64 decode → URL parameter!</p>
        <p>Flag: <code>FLAG{{chain_all_the_skills_together}}</code></p>
        <p style='margin-top:1rem'><a href='/' style='color:#5a6270;font-size:0.85rem;'>← Home</a></p>
        </body></html>"""
    return """<!DOCTYPE html><html><head>
    <link href='/static/fonts.css' rel='stylesheet'>
    <style>body{{background:#05060a;color:#c8d0d8;font-family:'JetBrains Mono',monospace;padding:2rem;}}
    h2{{color:#ff3860;}}</style></head><body>
    <h2>🔒 Access Denied</h2><p>Wrong key. Keep working the chain.</p>
    </body></html>"""


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9300, debug=False)
