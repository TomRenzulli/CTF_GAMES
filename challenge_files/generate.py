#!/usr/bin/env python3
"""Generate all static challenge files for BERA Cyber Training Academy."""
import base64
import os
import struct
import zlib

import pathlib
OUT = str(pathlib.Path(__file__).parent.resolve())

# ── Flag 02: hex-encoded flag hidden in a text file ──────────────────────────
flag02 = "FLAG{hex_decoded_you_found_me}"
hex_str = flag02.encode().hex()
with open(f"{OUT}/signal.txt", "w") as f:
    f.write("TRANSMISSION INTERCEPT LOG\n")
    f.write("="*40 + "\n")
    f.write("Timestamp: 2026-10-15T09:41:22Z\n")
    f.write("Source: Unknown\n")
    f.write("Message (encoded): ")
    f.write(hex_str + "\n")
    f.write("="*40 + "\n")
    f.write("Tip: Each pair of characters is a hex byte. Try: echo '...' | xxd -r -p\n")

# ── Flag 03: binary-encoded flag ─────────────────────────────────────────────
flag03 = "FLAG{bits_and_bytes_101}"
binary_str = " ".join(format(ord(c), '08b') for c in flag03)
with open(f"{OUT}/binary_message.txt", "w") as f:
    f.write("BINARY TRANSMISSION RECEIVED\n")
    f.write("-"*40 + "\n")
    f.write(binary_str + "\n")
    f.write("-"*40 + "\n")
    f.write("Tip: Each group of 8 bits is one character (ASCII). 01000001 = A\n")

# ── Flag 06: file with flag buried in strings output ─────────────────────────
flag06 = "FLAG{strings_reveals_all_secrets}"
with open(f"{OUT}/mystery.bin", "wb") as f:
    # Write random-ish bytes, then embed the flag, then more junk
    junk1 = bytes([0x89, 0x50, 0x4e, 0x47, 0x00, 0x00, 0xFF, 0xFE] * 20)
    junk2 = bytes(range(256)) * 3
    f.write(junk1)
    f.write(b"\x00\x00\x00")
    f.write(flag06.encode())
    f.write(b"\x00\x00\x00")
    f.write(junk2)
    f.write(b"JUNK DATA JUNK DATA JUNK DATA\x00\x00")
    f.write(b"SOME OTHER STRING HERE\x00")

# ── Flag 07: file where `file` command matters + strings ─────────────────────
flag07 = "FLAG{file_command_knows_all}"
# Make a valid ZIP with flag inside, but named .txt
import zipfile, io
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w') as zf:
    zf.writestr("readme.txt", f"You found the hidden archive!\nFlag: {flag07}\n")
buf.seek(0)
with open(f"{OUT}/definitely_a_text_file.txt", "wb") as f:
    f.write(buf.read())

# ── Flag 14: PNG with flag in EXIF/metadata comment ──────────────────────────
flag14 = "FLAG{metadata_hides_in_plain_sight}"
# Build a minimal valid PNG with a tEXt chunk containing the flag
def make_png_with_text(width=10, height=10, text_key="Comment", text_value=""):
    def chunk(name, data):
        c = name + data
        return struct.pack('>I', len(data)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)

    sig = b'\x89PNG\r\n\x1a\n'
    ihdr_data = struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0)
    ihdr = chunk(b'IHDR', ihdr_data)

    # minimal image data - red pixels
    raw = b''
    for y in range(height):
        raw += b'\x00' + b'\xff\x00\x00' * width
    compressed = zlib.compress(raw)
    idat = chunk(b'IDAT', compressed)

    text_payload = text_key.encode() + b'\x00' + text_value.encode()
    text_chunk = chunk(b'tEXt', text_payload)

    iend = chunk(b'IEND', b'')
    return sig + ihdr + text_chunk + idat + iend

png_data = make_png_with_text(text_key="Author", text_value=f"BERA Cyber | Flag: {flag14}")
with open(f"{OUT}/training_badge.png", "wb") as f:
    f.write(png_data)

# ── Flag 15: file with wrong extension (JPEG named .pdf) ─────────────────────
flag15 = "FLAG{magic_bytes_dont_lie}"
# Minimal valid JPEG
jpeg_data = bytes([
    0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
    0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
    0xFF, 0xFE,  # Comment marker
]) + struct.pack('>H', len(flag15) + 2) + flag15.encode() + bytes([0xFF, 0xD9])
with open(f"{OUT}/report.pdf", "wb") as f:
    f.write(jpeg_data)


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE: Network Traffic Analysis — packet captures
# Built with the dependency-free writer in pcapgen.py (no scapy in the image).
# ═══════════════════════════════════════════════════════════════════════════════
import sys
sys.path.insert(0, OUT)
from pcapgen import (Pcap, TcpStream, dns_query, ethernet, ipv4, tcp,
                     PROTO_TCP, SYN, ACK, RST)

# ── Challenge 21: cleartext credentials in an HTTP POST ─────────────────────
flag21 = "FLAG{cleartext_http_leaks_creds}"
cap = Pcap(1763051400.0)
# Decoy first: a normal page load, so the POST actually has to be found.
s = TcpStream(cap, "192.168.20.57", "192.168.20.10", 49211, 80).handshake()
s.client_says(b"GET /portal/login HTTP/1.1\r\nHost: hmi-portal.plant.local\r\n"
              b"User-Agent: Mozilla/5.0\r\nAccept: text/html\r\n\r\n")
s.server_says(b"HTTP/1.1 200 OK\r\nServer: lighttpd/1.4.59\r\n"
              b"Content-Type: text/html\r\nContent-Length: 74\r\n\r\n"
              b"<html><body><form method=post action=/portal/auth>...</form></body></html>")
s.teardown()
body = ("username=operator&password=" + flag21 + "&remember=1").encode()
s2 = TcpStream(cap, "192.168.20.57", "192.168.20.10", 49213, 80).handshake()
s2.client_says(b"POST /portal/auth HTTP/1.1\r\nHost: hmi-portal.plant.local\r\n"
               b"Content-Type: application/x-www-form-urlencoded\r\n"
               b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
s2.server_says(b"HTTP/1.1 302 Found\r\nLocation: /portal/dashboard\r\n"
               b"Set-Cookie: sid=8f21ac9e; Path=/\r\nContent-Length: 0\r\n\r\n")
s2.teardown()
cap.write(f"{OUT}/portal_capture.pcap")

# ── Challenge 22: flag split across TCP segments (follow the stream) ────────
flag22 = "FLAG{follow_the_whole_stream}"
cap = Pcap(1763052000.0)
s = TcpStream(cap, "192.168.20.57", "192.168.20.44", 50114, 9009).handshake()
s.server_says(b"220 maintenance-relay ready\r\n")
s.client_says(b"FETCH /maint/key\r\n")
# Deliberately fragmented: no single packet contains the whole flag.
for i in range(0, len(flag22), 5):
    s.server_says(flag22[i:i + 5].encode(), gap=0.0021 + i * 0.0001)
s.server_says(b"\r\n221 closing\r\n")
s.teardown()
cap.write(f"{OUT}/relay_session.pcap")

# ── Challenge 23: DNS exfiltration via hex-encoded subdomains ───────────────
flag23 = "FLAG{dns_is_an_exfil_channel}"
cap = Pcap(1763052600.0)
for i, host in enumerate(["update.plant.local", "ntp.plant.local", "mail.plant.local"]):
    dns_query(cap, "192.168.20.57", "192.168.20.2", host, 0x3000 + i, gap=0.42)
payload = flag23.encode().hex()
for i in range(0, len(payload), 16):
    dns_query(cap, "192.168.20.57", "192.168.20.2",
              f"{payload[i:i+16]}.d{i//16:02d}.tunnel.exfil-node.net",
              0x4000 + i, gap=0.31)
for i, host in enumerate(["cdn.plant.local", "wsus.plant.local"]):
    dns_query(cap, "192.168.20.57", "192.168.20.2", host, 0x5000 + i, gap=0.37)
cap.write(f"{OUT}/dns_traffic.pcap")

# ── Challenge 24: SYN scan, then a banner on the one open port ──────────────
flag24 = "FLAG{banner_grab_after_the_scan}"
cap = Pcap(1763053200.0)
attacker, target = "192.168.20.99", "192.168.20.31"
amac, tmac = "00:0c:29:7e:4d:11", "00:50:56:84:f1:0a"
scanned = [21, 22, 23, 25, 80, 110, 139, 443, 445, 502, 1433, 3306, 3389, 5900, 8080, 8443]
OPEN_PORT = 8291
ident = 100
for i, port in enumerate(scanned + [OPEN_PORT]):
    ident += 1
    seg = tcp(attacker, target, 44000 + i, port, 7000 + i * 100, 0, SYN)
    cap.add(ethernet(amac, tmac, ipv4(attacker, target, seg, PROTO_TCP, ident)), 0.0021)
    ident += 1
    if port == OPEN_PORT:
        seg = tcp(target, attacker, port, 44000 + i, 9000, 7000 + i * 100 + 1, SYN | ACK)
    else:
        seg = tcp(target, attacker, port, 44000 + i, 0, 7000 + i * 100 + 1, RST | ACK)
    cap.add(ethernet(tmac, amac, ipv4(target, attacker, seg, PROTO_TCP, ident)), 0.0004)
s = TcpStream(cap, attacker, target, 44300, OPEN_PORT,
              client_mac=amac, server_mac=tmac).handshake()
s.server_says(b"MaintSvc 2.1 (build 7741)\r\nmaint-token: " + flag24.encode() + b"\r\n")
s.client_says(b"QUIT\r\n")
s.teardown()
cap.write(f"{OUT}/scan_capture.pcap")


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE: Log Analysis & Detection — the first defensive content
# ═══════════════════════════════════════════════════════════════════════════════

# ── Challenge 25: SSH brute force, one success buried in the failures ───────
flag25 = "FLAG{one_success_among_the_failures}"
lines = []
t = 0
def ts(offset):
    m, sec = divmod(offset, 60)
    h, m = divmod(m, 60)
    return f"Nov 18 {2 + h:02d}:{m:02d}:{sec:02d}"
lines.append(f"{ts(0)} plc-jump sshd[2211]: Server listening on 0.0.0.0 port 22.")
lines.append(f"{ts(14)} plc-jump sshd[2240]: Accepted password for operator from 192.168.20.57 port 51022 ssh2")
lines.append(f"{ts(21)} plc-jump sshd[2240]: pam_unix(sshd:session): session opened for user operator")
t = 600
users = ["root", "admin", "oracle", "postgres", "operator", "scada", "ubuntu", "test"]
for i in range(96):
    u = users[i % len(users)]
    lines.append(f"{ts(t)} plc-jump sshd[{2300+i}]: Failed password for "
                 f"{'invalid user ' if u not in ('root','operator') else ''}{u} "
                 f"from 203.0.113.47 port {40000+i*7} ssh2")
    t += 2
# the needle: the single success from the attacking IP
lines.append(f"{ts(t)} plc-jump sshd[2399]: Accepted password for scada from 203.0.113.47 port 40701 ssh2")
lines.append(f"{ts(t+1)} plc-jump sshd[2399]: pam_unix(sshd:session): session opened for user scada")
lines.append(f"{ts(t+2)} plc-jump sshd[2399]: session marker {flag25}")
t += 10
for i in range(12):
    lines.append(f"{ts(t)} plc-jump sshd[{2420+i}]: Failed password for root from 203.0.113.47 port {41000+i*5} ssh2")
    t += 2
lines.append(f"{ts(t+30)} plc-jump sshd[2211]: Received signal 15; terminating.")
with open(f"{OUT}/auth.log", "w") as f:
    f.write("\n".join(lines) + "\n")

# ── Challenge 26: web recon — find the one request that succeeded ───────────
flag26 = "FLAG{read_the_status_codes}"
paths_404 = ["/admin", "/admin.php", "/wp-login.php", "/.git/config", "/phpmyadmin",
             "/backup.zip", "/config.php.bak", "/.env", "/server-status", "/cgi-bin/test.cgi",
             "/api/v1/users", "/old/", "/dev/", "/.svn/entries", "/web.config",
             "/actuator/health", "/.DS_Store", "/db.sql", "/console", "/login.bak"]
rows = []
clock = 0
def alog(ip, path, code, size, ua="Mozilla/5.0 (compatible; scanner/1.2)"):
    global clock
    clock += 1
    m, sec = divmod(clock, 60)
    stamp = f"18/Nov/2026:03:{m % 60:02d}:{sec:02d} +0000"
    rows.append(f'{ip} - - [{stamp}] "GET {path} HTTP/1.1" {code} {size} "-" "{ua}"')
alog("192.168.20.57", "/", 200, 1821, "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0")
alog("192.168.20.57", "/portal/login", 200, 2104, "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0")
for p in paths_404:
    alog("203.0.113.47", p, 404, 162)
# the needle: a 200 nobody should have got, carrying the flag
alog("203.0.113.47", f"/portal/.backup/credentials.txt?token={flag26}", 200, 448)
for p in ["/robots.txt", "/sitemap.xml", "/favicon.ico"]:
    alog("203.0.113.47", p, 404, 162)
alog("192.168.20.57", "/portal/dashboard", 200, 7733, "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0")
with open(f"{OUT}/access.log", "w") as f:
    f.write("\n".join(rows) + "\n")

# ── Challenge 27: impossible travel in VPN session logs ────────────────────
flag27 = "FLAG{two_countries_one_minute}"
vpn = ["# plant-vpn session log — generated 2026-11-18T06:00:00Z",
       "# fields: timestamp,user,src_ip,geo,action,session"]
normal = [
    ("2026-11-18T05:02:11Z", "j.harlow", "198.51.100.24", "US-NY", "connect", "s-41a7"),
    ("2026-11-18T05:02:12Z", "j.harlow", "198.51.100.24", "US-NY", "auth-ok", "s-41a7"),
    ("2026-11-18T05:19:40Z", "m.okafor", "198.51.100.77", "US-NY", "connect", "s-41b2"),
    ("2026-11-18T05:19:41Z", "m.okafor", "198.51.100.77", "US-NY", "auth-ok", "s-41b2"),
    ("2026-11-18T05:31:02Z", "d.lindqvist", "198.51.100.91", "US-NJ", "connect", "s-41c0"),
    ("2026-11-18T05:31:03Z", "d.lindqvist", "198.51.100.91", "US-NJ", "auth-ok", "s-41c0"),
    ("2026-11-18T05:44:55Z", "s.varga", "198.51.100.12", "US-NY", "connect", "s-41c9"),
    ("2026-11-18T05:44:56Z", "s.varga", "198.51.100.12", "US-NY", "auth-ok", "s-41c9"),
    # the needle: same account, two continents, 48 seconds apart
    ("2026-11-18T05:51:03Z", "m.okafor", "198.51.100.77", "US-NY", "auth-ok", "s-41b2"),
    ("2026-11-18T05:51:51Z", "m.okafor", "91.219.238.14", "RU-MOW", "auth-ok", "s-41d4"),
    ("2026-11-18T05:51:52Z", "m.okafor", "91.219.238.14", "RU-MOW", "note=" + flag27, "s-41d4"),
    ("2026-11-18T05:52:10Z", "m.okafor", "91.219.238.14", "RU-MOW", "privesc-request", "s-41d4"),
    ("2026-11-18T05:58:00Z", "j.harlow", "198.51.100.24", "US-NY", "disconnect", "s-41a7"),
]
for row in normal:
    vpn.append(",".join(row))
with open(f"{OUT}/vpn_sessions.log", "w") as f:
    f.write("\n".join(vpn) + "\n")

# ── Challenge 28: the live log was cleared; the rotated copy wasn't ─────────
flag28 = "FLAG{rotated_logs_remember}"
with open(f"{OUT}/plant_syslog.log", "w") as f:
    f.write("Nov 18 05:40:01 plc-jump systemd[1]: Started Rotate log files.\n")
    f.write("Nov 18 06:00:00 plc-jump rsyslogd: [origin software=\"rsyslogd\"] rsyslogd was HUPed\n")
    f.write("Nov 18 06:00:02 plc-jump kernel: audit: backlog limit exceeded\n")
    f.write("Nov 18 06:00:05 plc-jump auditd[812]: Audit daemon rotating log files\n")
    f.write("# NOTE: entries before 06:00 are not in this file. Check the rotated copy.\n")
with open(f"{OUT}/plant_syslog.log.1", "w") as f:
    f.write("Nov 18 05:12:44 plc-jump sudo: scada : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash\n")
    f.write("Nov 18 05:13:02 plc-jump kernel: [UFW BLOCK] SRC=203.0.113.47 DST=192.168.20.31 PROTO=TCP DPT=502\n")
    f.write("Nov 18 05:14:19 plc-jump auditd[812]: cleared audit trail by uid=0\n")
    f.write(f"Nov 18 05:14:20 plc-jump auditd[812]: pre-clear marker {flag28}\n")
    f.write("Nov 18 05:15:00 plc-jump sshd[2399]: pam_unix(sshd:session): session closed for user scada\n")


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE: Phishing & Email Forensics — raw .eml files
# ═══════════════════════════════════════════════════════════════════════════════

flag29 = "FLAG{received_headers_dont_lie}"
with open(f"{OUT}/phish_01.eml", "w") as f:
    f.write(f"""Delivered-To: operator@plant.local
Received: from mx01.plant.local (mx01.plant.local [192.168.20.25])
    by inbox.plant.local with LMTP id 8f21ac9e
    for <operator@plant.local>; Tue, 18 Nov 2026 07:14:52 -0500
Received: from relay-out.mailvendor.net (relay-out.mailvendor.net [203.0.113.200])
    by mx01.plant.local with ESMTPS id 44a1b7c2
    for <operator@plant.local>; Tue, 18 Nov 2026 07:14:49 -0500
Received: from smtp.bulk-sender.ru (smtp.bulk-sender.ru [91.219.238.14])
    by relay-out.mailvendor.net with ESMTP id 7c91ff03;
    Tue, 18 Nov 2026 07:14:41 -0500
    X-Origin-Note: {flag29}
From: "BNL IT Helpdesk" <helpdesk@bnl-support-portal.com>
To: <operator@plant.local>
Subject: ACTION REQUIRED: Your VPN certificate expires today
Date: Tue, 18 Nov 2026 07:14:38 -0500
Message-ID: <20261118121438.7c91ff03@smtp.bulk-sender.ru>
Content-Type: text/plain; charset=utf-8

Your VPN certificate expires in 4 hours. Renew now to avoid losing access.

Renew: http://bnl-support-portal.com/vpn/renew?u=operator

IT Helpdesk
""")

flag30 = "FLAG{spf_dkim_dmarc_all_failed}"
with open(f"{OUT}/phish_02.eml", "w") as f:
    f.write(f"""Delivered-To: m.okafor@plant.local
Received: from mx01.plant.local (mx01.plant.local [192.168.20.25])
    by inbox.plant.local with LMTP id 1a2b3c4d
    for <m.okafor@plant.local>; Tue, 18 Nov 2026 08:02:10 -0500
Authentication-Results: mx01.plant.local;
    spf=fail (sender IP is 91.219.238.14) smtp.mailfrom=bnl.gov;
    dkim=fail (signature did not verify) header.d=bnl.gov;
    dmarc=fail (p=REJECT) header.from=bnl.gov;
    x-audit-note={flag30}
Received-SPF: fail (bnl.gov: domain of bnl.gov does not designate
    91.219.238.14 as permitted sender) client-ip=91.219.238.14
From: "Payroll Services" <payroll@bnl.gov>
To: <m.okafor@plant.local>
Subject: Updated direct deposit form — signature needed
Date: Tue, 18 Nov 2026 08:02:04 -0500
Message-ID: <a71f@bnl.gov>
Content-Type: text/plain; charset=utf-8

Please review and sign the attached direct deposit update by end of day.

Payroll Services
""")

flag31 = "FLAG{hover_before_you_click}"
with open(f"{OUT}/phish_03.eml", "w") as f:
    f.write(f"""Delivered-To: d.lindqvist@plant.local
Received: from mx01.plant.local (mx01.plant.local [192.168.20.25])
    by inbox.plant.local with LMTP id 55ee77aa
    for <d.lindqvist@plant.local>; Tue, 18 Nov 2026 09:31:44 -0500
From: "Microsoft 365" <no-reply@notifications.microsoft.com>
To: <d.lindqvist@plant.local>
Subject: You have 3 quarantined messages
Date: Tue, 18 Nov 2026 09:31:40 -0500
Message-ID: <q3-55ee77aa@notifications.microsoft.com>
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<html><body style="font-family:Segoe UI,sans-serif">
<p>You have <b>3</b> messages held in quarantine.</p>
<p>
  <a href="https://login.microsoftonline.com/common/oauth2/authorize">
     https://login.microsoftonline.com/common/oauth2/authorize
  </a>
</p>
<p>
  <a href="http://plant-quarantine-review.cc/sso?r={flag31}">Review messages</a>
</p>
<p style="color:#888;font-size:11px">Microsoft Corporation, One Microsoft Way</p>
</body></html>
""")

flag32 = "FLAG{attachments_decode_to_payloads}"
import base64 as _b64
_att = _b64.b64encode(
    ("@echo off\r\n"
     "rem invoice_8871.pdf.bat — dropper stub\r\n"
     "powershell -nop -w hidden -enc <redacted>\r\n"
     f"rem marker: {flag32}\r\n").encode()).decode()
_att_wrapped = "\n".join(_att[i:i + 76] for i in range(0, len(_att), 76))
with open(f"{OUT}/phish_04.eml", "w") as f:
    f.write(f"""Delivered-To: s.varga@plant.local
Received: from mx01.plant.local (mx01.plant.local [192.168.20.25])
    by inbox.plant.local with LMTP id 99cc11bb
    for <s.varga@plant.local>; Tue, 18 Nov 2026 10:05:12 -0500
From: "Accounts Payable" <ap@vendor-invoices.biz>
To: <s.varga@plant.local>
Subject: Invoice 8871 overdue
Date: Tue, 18 Nov 2026 10:05:08 -0500
Message-ID: <inv8871@vendor-invoices.biz>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_Part_8871"

------=_Part_8871
Content-Type: text/plain; charset=utf-8

Invoice 8871 is 30 days overdue. Details attached.

------=_Part_8871
Content-Type: application/octet-stream; name="invoice_8871.pdf.bat"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="invoice_8871.pdf.bat"

{_att_wrapped}
------=_Part_8871--
""")


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE: OT / ICS Fundamentals
# ═══════════════════════════════════════════════════════════════════════════════

def modbus_frame(txid, unit, pdu):
    """MBAP header + PDU. Wireshark dissects TCP port 502 as Modbus/TCP."""
    return struct.pack(">HHHB", txid, 0, len(pdu) + 1, unit) + pdu

# ── Challenge 33: reading Modbus traffic (no auth anywhere in it) ──────────
flag33 = "FLAG{modbus_has_no_authentication}"
cap = Pcap(1763054000.0)
s = TcpStream(cap, "192.168.20.57", "192.168.20.31", 51500, 502).handshake()
# poll loop: read holding registers 0-9 from unit 1
for i in range(6):
    s.client_says(modbus_frame(0x0100 + i, 1, struct.pack(">BHH", 0x03, 0, 10)), gap=0.25)
    regs = b"".join(struct.pack(">H", v) for v in (480 + i, 1013, 72, 1, 0, 340, 15, 2, 0, 1))
    s.server_says(modbus_frame(0x0100 + i, 1, struct.pack(">BB", 0x03, 20) + regs), gap=0.012)
# an operator comment smuggled through a Read Device Identification response
s.client_says(modbus_frame(0x0200, 1, struct.pack(">BBB", 0x2B, 0x0E, 0x01)), gap=0.3)
s.server_says(modbus_frame(0x0200, 1, struct.pack(">BBBBBB", 0x2B, 0x0E, 0x01, 0x81, 0x00, 0x01)
                           + bytes([0x00, len(flag33)]) + flag33.encode()), gap=0.02)
s.teardown()
cap.write(f"{OUT}/modbus_poll.pcap")

# ── Challenge 34: unauthenticated Write Single Coil trips a breaker ────────
flag34 = "FLAG{coil_forced_breaker_opened}"
cap = Pcap(1763054600.0)
s = TcpStream(cap, "203.0.113.47", "192.168.20.31", 52200, 502).handshake()
s.client_says(modbus_frame(0x0300, 1, struct.pack(">BHH", 0x01, 0, 8)), gap=0.18)
s.server_says(modbus_frame(0x0300, 1, struct.pack(">BBB", 0x01, 1, 0b00000001)), gap=0.01)
# Write Single Coil, address 3, value 0xFF00 (= ON) — no credentials, no refusal
s.client_says(modbus_frame(0x0301, 1, struct.pack(">BHH", 0x05, 3, 0xFF00)), gap=0.4)
s.server_says(modbus_frame(0x0301, 1, struct.pack(">BHH", 0x05, 3, 0xFF00)), gap=0.01)
s.client_says(modbus_frame(0x0302, 1, struct.pack(">BHH", 0x01, 0, 8)), gap=0.2)
s.server_says(modbus_frame(0x0302, 1, struct.pack(">BBB", 0x01, 1, 0b00001001)), gap=0.01)
s.teardown()
with open(f"{OUT}/breaker_alarm.log", "w") as f:
    f.write("# SCADA alarm journal — BUS-2 feeder\n")
    f.write("2026-11-18T05:13:40Z,INFO,BUS-2,coil[3],state=0,source=hmi-01\n")
    f.write("2026-11-18T05:13:58Z,CRITICAL,BUS-2,coil[3],state=1,source=192.168.20.31,"
            "note=write_single_coil accepted without authentication\n")
    f.write("2026-11-18T05:13:58Z,CRITICAL,BUS-2,breaker,position=OPEN,"
            f"ack_token={flag34}\n")
    f.write("2026-11-18T05:14:30Z,WARN,BUS-2,load,shed_kw=1180\n")
cap.write(f"{OUT}/modbus_write.pcap")

# ── Challenge 35: cleartext Telnet login to a PLC ──────────────────────────
flag35 = "FLAG{telnet_to_a_plc_in_2026}"
cap = Pcap(1763055200.0)
s = TcpStream(cap, "203.0.113.47", "192.168.20.33", 53100, 23).handshake()
s.server_says(b"\r\nSIMATIC-compatible PLC gateway v3.2\r\nlogin: ")
# Telnet echoes input one character at a time — the password is never in one packet
for ch in "maintenance":
    s.client_says(ch.encode(), gap=0.09)
s.client_says(b"\r\n", gap=0.12)
s.server_says(b"\r\npassword: ")
for ch in "Plant#2026":
    s.client_says(ch.encode(), gap=0.11)
s.client_says(b"\r\n", gap=0.14)
s.server_says(b"\r\nLogin OK. Privilege: ENGINEER\r\n")
s.server_says(b"session-key: " + flag35.encode() + b"\r\nPLC> ")
s.client_says(b"show runtime\r\n", gap=0.5)
s.server_says(b"cycle=12ms  mode=RUN  retain=OK\r\nPLC> ")
s.client_says(b"logout\r\n", gap=0.4)
s.teardown()
cap.write(f"{OUT}/plc_telnet.pcap")

# ── Challenge 36: HMI config — safety vs uptime (the SRP triad) ────────────
flag36 = "FLAG{safety_outranks_uptime}"
with open(f"{OUT}/hmi_station.conf", "w") as f:
    f.write(f"""; HMI-01 station configuration — Plant Bus 2
; Change control: any edit here requires an SRP impact review.
; SRP = Safety / Reliability / Performance. Rank the vertices before you act.

[station]
name          = HMI-01
area          = BUS-2
firmware      = 3.2.1
patch_window  = none            ; never patched during production

[protocol]
modbus_tcp    = enabled
port          = 502
auth          = none            ; protocol provides none
write_allowed = true
allow_from    = 0.0.0.0/0       ; any host on the plant LAN may write coils

[interlocks]
; An interlock is a SAFETY function. Disabling one to keep the line running
; trades Safety away for Performance. That trade is never the operator's to make.
overpressure_trip   = enabled
emergency_stop      = enabled
bypass_requires     = two-person authorization

[review]
; Classify each proposed change by which vertex it protects, then rank:
;   Safety      > Reliability > Performance
; An engineer who proposes "bypass the overpressure trip so we hit quota"
; has inverted that order. The correct answer to that proposal is always no.
srp_precedence = {flag36}
last_review    = 2026-11-01
reviewer       = d.lindqvist
""")


print("All challenge files generated.")
for fn in sorted(os.listdir(OUT)):
    if fn != "generate.py":
        size = os.path.getsize(f"{OUT}/{fn}")
        print(f"  {fn:40s} {size:6d} bytes")
