# secure_protocol.py
# Secure Message Protocol — Blowfish-CBC + HMAC-SHA256 + Replay Protection
# Project : Offline Secured Chat Application
# Author  : Jawad Khalid

import base64
import hashlib
import hmac as _hmac
import json
import os
import socket
import struct

PROTOCOL_VERSION = 1
BLOCK_SIZE = 8  # Blowfish block size in bytes


def derive_keys(shared_secret: bytes) -> tuple:
    """
    Derive two separate keys from one shared secret using SHA-256:
      enc_key : 32 bytes — used for Blowfish encryption
      mac_key : 32 bytes — used for HMAC-SHA256 integrity check
    """
    seed = hashlib.sha256(shared_secret).digest()
    enc_key = hashlib.sha256(seed + b"ENC").digest()[:32]  # 32 bytes → fits Blowfish max 56
    mac_key = hashlib.sha256(seed + b"MAC").digest()
    return enc_key, mac_key


# ── Low-level socket helpers ──────────────────────────────────────────────────

def _recv_exact(sock: socket.socket, size: int) -> bytes:
    """Read exactly `size` bytes from socket — blocks until done."""
    chunks, received = [], 0
    while received < size:
        chunk = sock.recv(size - received)
        if not chunk:
            raise ConnectionError("Connection closed while receiving data.")
        chunks.append(chunk)
        received += len(chunk)
    return b"".join(chunks)


def send_packet(sock: socket.socket, packet: dict) -> None:
    """Serialize packet to JSON and send with a 4-byte length header."""
    raw = json.dumps(packet, separators=(",", ":")).encode("utf-8")
    header = struct.pack(">I", len(raw))
    sock.sendall(header + raw)


def recv_packet(sock: socket.socket) -> dict:
    """Read a length-prefixed JSON packet from the socket."""
    header = _recv_exact(sock, 4)
    (size,) = struct.unpack(">I", header)
    if size <= 0 or size > 10 * 1024 * 1024:  # 10 MB max
        raise ValueError(f"Invalid packet size: {size}")
    return json.loads(_recv_exact(sock, size).decode("utf-8"))


# ── Secure packet build / parse ───────────────────────────────────────────────

def build_secure_packet(cipher, mac_key: bytes, plaintext: str, seq: int) -> dict:
    """
    Encrypt a message and produce an authenticated packet:
      1. Generate a random 8-byte IV
      2. Encrypt with Blowfish-CBC
      3. Compute HMAC-SHA256 over (seq || iv || ciphertext)
      4. Return JSON-safe dict with base64-encoded fields
    """
    iv = os.urandom(BLOCK_SIZE)
    ciphertext = cipher.encrypt_message_cbc(plaintext, iv)
    aad = seq.to_bytes(8, "big")
    tag = _hmac.new(mac_key, aad + iv + ciphertext, hashlib.sha256).digest()
    return {
        "version":    PROTOCOL_VERSION,
        "seq":        seq,
        "iv":         base64.b64encode(iv).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "hmac":       base64.b64encode(tag).decode("ascii"),
    }


def parse_secure_packet(cipher, mac_key: bytes, packet: dict, last_seq: int) -> tuple:
    """
    Authenticate and decrypt a received packet:
      1. Check protocol version
      2. Enforce strictly-increasing sequence numbers (anti-replay)
      3. Verify HMAC — reject if tampered
      4. Decrypt and return (plaintext, seq)
    """
    if packet.get("version") != PROTOCOL_VERSION:
        raise ValueError("Unsupported protocol version.")

    seq = packet.get("seq")
    if not isinstance(seq, int):
        raise ValueError("Invalid sequence number.")
    if seq <= last_seq:
        raise ValueError("Replay or out-of-order packet rejected.")

    iv         = base64.b64decode(packet["iv"])
    ciphertext = base64.b64decode(packet["ciphertext"])
    recv_tag   = base64.b64decode(packet["hmac"])

    expected = _hmac.new(
        mac_key,
        seq.to_bytes(8, "big") + iv + ciphertext,
        hashlib.sha256,
    ).digest()

    if not _hmac.compare_digest(recv_tag, expected):
        raise ValueError("⚠️  Message integrity check failed — possible tampering!")

    plaintext = cipher.decrypt_message_cbc(ciphertext, iv)
    return plaintext, seq