"""
Cyber Training Academy — 20-Flag Beginner Progression CTF
Single container, port 9300.
Each flag teaches exactly one concept before the next builds on it.
"""
from flask import (Flask, request, render_template_string,
                   redirect, url_for, session, send_from_directory,
                   Response)
import secrets, base64, sqlite3, os, subprocess, hashlib

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

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
                 "<code class='block-code'>SYNT{ebg13_vf_whfg_n_cneebc}</code><br><br>"
                 "Rotate each letter 13 positions back to read the flag.<br><br>"
                 "<b>Hint:</b> <code>echo 'SYNT{ebg13_vf_whfg_n_cneebc}' | tr 'A-Za-z' 'N-ZA-Mn-za-m'</code>",
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

FLAG_MAP = {c["flag"]: c["id"] for c in CHALLENGES}
TOTAL_POINTS = sum(c["points"] for c in CHALLENGES)

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

# ── Main page template ────────────────────────────────────────────────────────
BASE_STYLE = """
:root {
  --bg: #05060a;
  --surface: #0d0f18;
  --border: rgba(0,255,157,0.15);
  --neon: #00ff9d;
  --neon2: #2de2ff;
  --text: #c8d0d8;
  --dim: #5a6270;
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
code {
  background: rgba(0,255,157,0.07);
  padding: 0.1rem 0.35rem;
  border-radius: 3px;
  color: var(--neon2);
  font-size: 0.9em;
}
"""

HEADER_HTML = """
<header style="border-bottom:1px solid var(--border);padding:1rem 2rem;display:flex;align-items:center;gap:1.5rem;background:rgba(0,255,157,0.03);">
  <span style="font-size:1.4rem;font-weight:700;color:var(--neon);letter-spacing:0.05em;">🛡 CYBER</span>
  <span style="color:var(--dim);font-size:0.75rem;letter-spacing:0.2em;">TRAINING ACADEMY</span>
  <span style="margin-left:auto;font-size:0.8rem;color:var(--dim);">
    Score: <b style="color:var(--neon)">{{ score }}</b> /
    <span style="color:var(--dim)">{{ total }}</span> pts &nbsp;|&nbsp;
    Solved: <b style="color:var(--neon)">{{ solved_count }}</b> / 20
  </span>
  <a href="/" style="font-size:0.8rem;color:var(--dim);">Home</a>
</header>
"""

INDEX_PAGE = """<!DOCTYPE html><html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cyber Training Academy</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
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
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1.2rem;
  background: var(--surface);
  cursor: pointer;
  transition: all 0.2s;
  position: relative;
}
.card:hover { border-color: var(--neon); box-shadow: 0 0 16px rgba(0,255,157,0.12); }
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
</style>
</head>
<body>
<!-- FLAG{source_code_tells_all} -->
<header style="border-bottom:1px solid var(--border);padding:1rem 2rem;display:flex;align-items:center;gap:1.5rem;background:rgba(0,255,157,0.03);">
  <span style="font-size:1.4rem;font-weight:700;color:var(--neon);letter-spacing:0.05em;">🛡 CYBER</span>
  <span style="color:var(--dim);font-size:0.75rem;letter-spacing:0.2em;">TRAINING ACADEMY</span>
  <span style="margin-left:auto;font-size:0.8rem;color:var(--dim);">
    Score: <b style="color:var(--neon)">{{ score }}</b> / {{ total }} pts &nbsp;|&nbsp;
    Solved: <b style="color:var(--neon)">{{ solved_count }}</b> / 20
  </span>
  <a href="/" style="font-size:0.8rem;color:var(--dim);">Challenges</a>
  <a href="/docs" style="font-size:0.8rem;color:var(--dim);">Documents</a>
</header>
<div class="hero">
  <h1>Training Academy</h1>
  <p>20 PROGRESSIVE CHALLENGES · BUILD SKILLS FROM ZERO · CYBER CTF CLUB</p>
  <div class="progress-bar-wrap"><div class="progress-bar" style="width:{{ pct }}%"></div></div>
  <div class="stats">{{ score }} / {{ total }} points &nbsp;·&nbsp; {{ solved_count }} / 20 solved &nbsp;·&nbsp; {{ pct }}% complete</div>
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
{% set categories = ['Encoding','Recon','File Analysis','Crypto','Web','Forensics','Auth','Injection','Chain'] %}
{% for cat in categories %}
  {% set cat_challenges = challenges|selectattr('category','equalto',cat)|list %}
  {% if cat_challenges %}
  <div class="cat-row">{{ cat }}</div>
  {% for c in cat_challenges %}
  <div class="card {% if c.id in solved %}solved{% endif %}" onclick="location.href='/challenge/{{ c.id }}'">
    {% if c.id in solved %}<span class="solved-badge">✓ SOLVED</span>{% endif %}
    <div class="card-num">CHALLENGE {{ '%02d'|format(c.id) }}</div>
    <div class="card-title">{{ c.title }}</div>
    <div class="card-meta">
      <span class="cat-badge">{{ c.category }}</span>
      <span class="pts">{{ c.points }} pts</span>
    </div>
  </div>
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
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>
""" + BASE_STYLE + """
.wrap { max-width: 760px; margin: 0 auto; padding: 2rem; }
.back { color: var(--dim); font-size:0.8rem; margin-bottom:1.5rem; display:block; }
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
</style>
</head>
<body>
<header style="border-bottom:1px solid var(--border);padding:1rem 2rem;display:flex;align-items:center;gap:1.5rem;background:rgba(0,255,157,0.03);">
  <span style="font-size:1.2rem;font-weight:700;color:var(--neon);">🛡 CYBER</span>
  <span style="color:var(--dim);font-size:0.75rem;letter-spacing:0.2em;">TRAINING ACADEMY</span>
  <span style="margin-left:auto;font-size:0.8rem;color:var(--dim);">
    Score: <b style="color:var(--neon)">{{ score }}</b> pts
  </span>
  <a href="/" style="font-size:0.8rem;color:var(--dim);">← All Challenges</a>
  <a href="/docs" style="font-size:0.8rem;color:var(--dim);">Documents</a>
</header>
<div class="wrap">
  <div class="cnum">CHALLENGE {{ '%02d'|format(c.id) }} of 20</div>
  <div class="ctitle">{{ c.title }} <span class="pts-badge">{{ c.points }} pts</span></div>
  <div class="skill-tag">🎓 Skill: {{ c.skill }}</div>

  {% if solved %}
  <div class="solved-banner">✅ CHALLENGE SOLVED! +{{ c.points }} points</div>
  {% endif %}
  {% if error %}
  <div class="error-banner">❌ {{ error }}</div>
  {% endif %}

  <div class="story">{{ c.story|safe }}</div>

  <form class="flag-form" method="POST">
    <input class="flag-input" name="flag" placeholder="FLAG{...}" autocomplete="off" {% if solved %}disabled{% endif %}>
    <button class="submit-btn" type="submit" {% if solved %}disabled{% endif %}>Submit Flag</button>
  </form>

  {% if c.notes %}
  <div class="notes-section">
    <button class="notes-toggle" onclick="toggleNotes(this)" aria-expanded="false">
      📖 &nbsp;Training Notes — Key Concepts for This Challenge
      <i class="chevron">▼</i>
    </button>
    <div class="notes-body" id="notes-body">
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
    {% if c.id > 1 %}
    <a href="/challenge/{{ c.id - 1 }}" class="nav-btn">← Challenge {{ c.id - 1 }}</a>
    {% endif %}
    <a href="/" class="nav-btn" style="margin-left:auto;">All Challenges</a>
    {% if c.id < 20 %}
    <a href="/challenge/{{ c.id + 1 }}" class="nav-btn">Challenge {{ c.id + 1 }} →</a>
    {% endif %}
  </div>
</div>
<script>
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
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
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
<header style="border-bottom:1px solid var(--border);padding:1rem 2rem;display:flex;align-items:center;gap:1.5rem;background:rgba(0,255,157,0.03);">
  <span style="font-size:1.4rem;font-weight:700;color:var(--neon);letter-spacing:0.05em;">🛡 CYBER</span>
  <span style="color:var(--dim);font-size:0.75rem;letter-spacing:0.2em;">TRAINING ACADEMY</span>
  <span style="margin-left:auto;font-size:0.8rem;color:var(--dim);">
    Score: <b style="color:var(--neon)">{{ score }}</b> pts
  </span>
  <a href="/" style="font-size:0.8rem;color:var(--dim);">Challenges</a>
  <a href="/docs" style="font-size:0.8rem;color:var(--dim);">Documents</a>
</header>
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

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    solved = get_solved()
    score = get_score()
    pct = round(score / TOTAL_POINTS * 100)
    flash = request.args.get("flash", "")
    error = request.args.get("error", "")
    return render_template_string(INDEX_PAGE,
        challenges=CHALLENGES, solved=solved, score=score,
        total=TOTAL_POINTS, solved_count=len(solved), pct=pct,
        flash=flash, error=error)


@app.route("/challenge/<int:cid>", methods=["GET", "POST"])
def challenge(cid):
    c = next((x for x in CHALLENGES if x["id"] == cid), None)
    if not c:
        return "Challenge not found", 404
    solved_ids = get_solved()
    already_solved = cid in solved_ids
    error = ""
    if request.method == "POST":
        submitted = request.form.get("flag", "").strip()
        if submitted == c["flag"]:
            mark_solved(c["flag"])
            already_solved = True
        else:
            error = f"Incorrect flag. Keep trying!"
    return render_template_string(CHALLENGE_PAGE,
        c=c, solved=already_solved, error=error, score=get_score())


# ── File downloads ────────────────────────────────────────────────────────────
@app.route("/files/<path:filename>")
def files(filename):
    return send_from_directory("/app/challenge_files", filename)


# ── Documents ─────────────────────────────────────────────────────────────────
DOCS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "docs")

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
    return render_template_string(DOCS_PAGE, docs=entries, score=get_score())


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
    <link href='https://fonts.googleapis.com/css2?family=JetBrains+Mono&display=swap' rel='stylesheet'>
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
    <link href='https://fonts.googleapis.com/css2?family=JetBrains+Mono&display=swap' rel='stylesheet'>
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
    <link href='https://fonts.googleapis.com/css2?family=JetBrains+Mono&display=swap' rel='stylesheet'>
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
    <link href='https://fonts.googleapis.com/css2?family=JetBrains+Mono&display=swap' rel='stylesheet'>
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
    <link href='https://fonts.googleapis.com/css2?family=JetBrains+Mono&display=swap' rel='stylesheet'>
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
                <link href='https://fonts.googleapis.com/css2?family=JetBrains+Mono&display=swap' rel='stylesheet'>
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
    <link href='https://fonts.googleapis.com/css2?family=JetBrains+Mono&display=swap' rel='stylesheet'>
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
    <link href='https://fonts.googleapis.com/css2?family=JetBrains+Mono&display=swap' rel='stylesheet'>
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
    <link href='https://fonts.googleapis.com/css2?family=JetBrains+Mono&display=swap' rel='stylesheet'>
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
    <link href='https://fonts.googleapis.com/css2?family=JetBrains+Mono&display=swap' rel='stylesheet'>
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
        <link href='https://fonts.googleapis.com/css2?family=JetBrains+Mono&display=swap' rel='stylesheet'>
        <style>body{{background:#05060a;color:#c8d0d8;font-family:'JetBrains Mono',monospace;padding:2rem;}}
        code{{background:rgba(0,255,157,0.1);padding:0.2rem 0.4rem;border-radius:3px;color:#2de2ff;}}
        h2{{color:#00ff9d;}}</style></head><body>
        <h2>🏆 FINAL VAULT UNLOCKED</h2>
        <p>You chained robots.txt → Base64 decode → URL parameter!</p>
        <p>Flag: <code>FLAG{{chain_all_the_skills_together}}</code></p>
        <p style='margin-top:1rem'><a href='/' style='color:#5a6270;font-size:0.85rem;'>← Home</a></p>
        </body></html>"""
    return """<!DOCTYPE html><html><head>
    <link href='https://fonts.googleapis.com/css2?family=JetBrains+Mono&display=swap' rel='stylesheet'>
    <style>body{{background:#05060a;color:#c8d0d8;font-family:'JetBrains Mono',monospace;padding:2rem;}}
    h2{{color:#ff3860;}}</style></head><body>
    <h2>🔒 Access Denied</h2><p>Wrong key. Keep working the chain.</p>
    </body></html>"""


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9300, debug=False)
