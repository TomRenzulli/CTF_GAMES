#!/usr/bin/env python3
"""Minimal pure-Python pcap writer for generating training captures.

No scapy dependency — the classic libpcap format is a 24-byte global header
followed by (16-byte record header + raw frame) per packet, so building valid
Ethernet/IPv4/TCP/UDP frames by hand is straightforward and keeps the container
dependency-free. Checksums are computed properly so Wireshark doesn't flag them.
"""
import struct

LINKTYPE_ETHERNET = 1
PROTO_TCP = 6
PROTO_UDP = 17

# TCP flags
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def _checksum(data: bytes) -> int:
    """Standard internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def mac(s: str) -> bytes:
    return bytes(int(p, 16) for p in s.split(":"))


def ip(s: str) -> bytes:
    return bytes(int(p) for p in s.split("."))


def ethernet(src: str, dst: str, payload: bytes, ethertype: int = 0x0800) -> bytes:
    return mac(dst) + mac(src) + struct.pack(">H", ethertype) + payload


def ipv4(src: str, dst: str, payload: bytes, proto: int, ident: int = 0, ttl: int = 64) -> bytes:
    ver_ihl = 0x45
    total_len = 20 + len(payload)
    header = struct.pack(">BBHHHBBH", ver_ihl, 0, total_len, ident, 0x4000, ttl, proto, 0)
    header += ip(src) + ip(dst)
    csum = _checksum(header)
    header = header[:10] + struct.pack(">H", csum) + header[12:]
    return header + payload


def _l4_checksum(src: str, dst: str, proto: int, segment: bytes) -> int:
    pseudo = ip(src) + ip(dst) + struct.pack(">BBH", 0, proto, len(segment))
    return _checksum(pseudo + segment)


def tcp(src_ip: str, dst_ip: str, sport: int, dport: int, seq: int, ack: int,
        flags: int, payload: bytes = b"", window: int = 64240) -> bytes:
    offset_flags = (5 << 12) | flags
    seg = struct.pack(">HHIIHHHH", sport, dport, seq, ack, offset_flags, window, 0, 0) + payload
    csum = _l4_checksum(src_ip, dst_ip, PROTO_TCP, seg)
    seg = seg[:16] + struct.pack(">H", csum) + seg[18:]
    return seg


def udp(src_ip: str, dst_ip: str, sport: int, dport: int, payload: bytes) -> bytes:
    seg = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    csum = _l4_checksum(src_ip, dst_ip, PROTO_UDP, seg) or 0xFFFF
    return seg[:6] + struct.pack(">H", csum) + seg[8:]


class Pcap:
    """Accumulates frames and writes a classic .pcap file."""

    def __init__(self, start_time: float = 1763000000.0):
        self.frames = []
        self.t = start_time

    def add(self, frame: bytes, gap: float = 0.000250):
        self.t += gap
        self.frames.append((self.t, frame))

    def write(self, path: str):
        with open(path, "wb") as f:
            # magic, major, minor, tz, sigfigs, snaplen, network
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535,
                                LINKTYPE_ETHERNET))
            for ts, frame in self.frames:
                sec = int(ts)
                usec = int(round((ts - sec) * 1_000_000))
                if usec >= 1_000_000:        # rounding can push it over
                    sec += 1
                    usec -= 1_000_000
                f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
                f.write(frame)
        return path


class TcpStream:
    """Builds a complete TCP conversation: handshake, data, teardown."""

    def __init__(self, cap: Pcap, client_ip: str, server_ip: str, sport: int, dport: int,
                 client_mac: str = "00:0c:29:1a:2b:3c",
                 server_mac: str = "00:50:56:84:f1:0a"):
        self.cap, self.cip, self.sip = cap, client_ip, server_ip
        self.sport, self.dport = sport, dport
        self.cmac, self.smac = client_mac, server_mac
        self.cseq, self.sseq = 1000, 5000
        self.ident = 1

    def _send(self, from_client: bool, flags: int, payload: bytes = b"", gap: float = 0.00025):
        self.ident += 1
        if from_client:
            seg = tcp(self.cip, self.sip, self.sport, self.dport,
                      self.cseq, self.sseq, flags, payload)
            pkt = ipv4(self.cip, self.sip, seg, PROTO_TCP, self.ident)
            frame = ethernet(self.cmac, self.smac, pkt)
            self.cseq += len(payload) + (1 if flags & (SYN | FIN) else 0)
        else:
            seg = tcp(self.sip, self.cip, self.dport, self.sport,
                      self.sseq, self.cseq, flags, payload)
            pkt = ipv4(self.sip, self.cip, seg, PROTO_TCP, self.ident)
            frame = ethernet(self.smac, self.cmac, pkt)
            self.sseq += len(payload) + (1 if flags & (SYN | FIN) else 0)
        self.cap.add(frame, gap)

    def handshake(self):
        self._send(True, SYN)
        self._send(False, SYN | ACK, gap=0.0004)
        self._send(True, ACK)
        return self

    def client_says(self, data: bytes, gap: float = 0.0012):
        self._send(True, PSH | ACK, data, gap)
        self._send(False, ACK, gap=0.0003)
        return self

    def server_says(self, data: bytes, gap: float = 0.0015):
        self._send(False, PSH | ACK, data, gap)
        self._send(True, ACK, gap=0.0003)
        return self

    def teardown(self):
        self._send(True, FIN | ACK)
        self._send(False, ACK, gap=0.0003)
        self._send(False, FIN | ACK, gap=0.0006)
        self._send(True, ACK, gap=0.0003)
        return self


def dns_query(cap: Pcap, client_ip: str, server_ip: str, qname: str,
              txid: int, sport: int = 51000, gap: float = 0.0035):
    """A single A-record query (no response — exfil only cares about the query)."""
    labels = b"".join(bytes([len(p)]) + p.encode() for p in qname.split(".")) + b"\x00"
    payload = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0) + labels + struct.pack(">HH", 1, 1)
    seg = udp(client_ip, server_ip, sport, 53, payload)
    cap.add(ethernet("00:0c:29:1a:2b:3c", "00:50:56:84:f1:0a",
                     ipv4(client_ip, server_ip, seg, PROTO_UDP, txid)), gap)
