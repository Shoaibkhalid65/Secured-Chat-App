import base64
import hashlib
import hmac
import json
import os
import socket
import struct


PROTOCOL_VERSION = 1
BLOCK_SIZE = 8


def derive_keys(shared_secret: bytes) -> tuple[bytes, bytes]:
    seed = hashlib.sha256(shared_secret).digest()
    enc_key = hashlib.sha256(seed + b"ENC").digest()[:32]
    mac_key = hashlib.sha256(seed + b"MAC").digest()
    return enc_key, mac_key


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = []
    received = 0
    while received < size:
        chunk = sock.recv(size - received)
        if not chunk:
            raise ConnectionError("Connection closed while receiving data.")
        chunks.append(chunk)
        received += len(chunk)
    return b"".join(chunks)


def send_packet(sock: socket.socket, packet: dict) -> None:
    raw = json.dumps(packet, separators=(",", ":")).encode("utf-8")
    header = struct.pack(">I", len(raw))
    sock.sendall(header + raw)


def recv_packet(sock: socket.socket) -> dict:
    header = _recv_exact(sock, 4)
    (size,) = struct.unpack(">I", header)
    if size <= 0:
        raise ValueError("Invalid packet size.")
    payload = _recv_exact(sock, size)
    return json.loads(payload.decode("utf-8"))


def build_secure_packet(cipher, mac_key: bytes, plaintext: str, seq: int) -> dict:
    iv = os.urandom(BLOCK_SIZE)
    ciphertext = cipher.encrypt_message_cbc(plaintext, iv)
    aad = seq.to_bytes(8, "big")
    tag = hmac.new(mac_key, aad + iv + ciphertext, hashlib.sha256).digest()
    return {
        "version": PROTOCOL_VERSION,
        "seq": seq,
        "iv": base64.b64encode(iv).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "hmac": base64.b64encode(tag).decode("ascii"),
    }


def parse_secure_packet(cipher, mac_key: bytes, packet: dict, last_seq: int) -> tuple[str, int]:
    version = packet.get("version")
    if version != PROTOCOL_VERSION:
        raise ValueError("Unsupported protocol version.")

    seq = packet.get("seq")
    if not isinstance(seq, int):
        raise ValueError("Invalid sequence number.")
    if seq <= last_seq:
        raise ValueError("Replay or out-of-order packet rejected.")

    iv = base64.b64decode(packet["iv"])
    ciphertext = base64.b64decode(packet["ciphertext"])
    recv_tag = base64.b64decode(packet["hmac"])

    expected = hmac.new(mac_key, seq.to_bytes(8, "big") + iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(recv_tag, expected):
        raise ValueError("Message integrity check failed.")

    plaintext = cipher.decrypt_message_cbc(ciphertext, iv)
    return plaintext, seq