# 🔐 Offline Secured Chat

> **End-to-end encrypted peer-to-peer messaging over local networks — powered by a from-scratch Blowfish cipher implementation.**

A fully working encrypted chat application where every message is locked with the **Blowfish block cipher** before it ever leaves your machine. No cloud, no server infrastructure, no third parties. Two devices. One shared key. Zero compromise.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Dependencies](https://img.shields.io/badge/Dependencies-Standard%20Library%20Only-lightgrey)
![Status](https://img.shields.io/badge/Status-Academic%20Project-orange)

---

## 📑 Table of Contents

- [Why I Built This](#-why-i-built-this)
- [Demo](#-demo)
- [What This Is](#-what-this-is)
- [Architecture Diagram](#-architecture-diagram)
- [How It Works](#-how-it-works)
- [The Blowfish Algorithm — From Scratch](#-the-blowfish-algorithm--from-scratch)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
- [Android Support](#-android-support)
- [Network Modes](#-network-modes)
- [Test Cases](#-test-cases)
- [Security Properties](#️-security-properties)
- [Threat Model — What This Does *Not* Protect Against](#-threat-model--what-this-does-not-protect-against)
- [Known Limitations](#known-limitations)
- [Where This Can Be Used](#-where-this-can-be-used)
- [Scope and Future Direction](#-scope-and-future-direction)
- [What I Learned](#-what-i-learned)
- [Impact](#-impact)
- [Built With](#️-built-with)
- [References](#-references)
- [About Me](#-about-me)
- [License](#-license)

---

## 💡 Why I Built This

Most developers use encryption libraries without ever seeing what happens inside them. I wanted to understand — not just call `encrypt()`, but actually build the cipher, the key schedule, the authentication layer, and the network protocol myself, from the ground up, using nothing but the Python standard library.

This project started as a 6th-semester Computer Networking assignment, but it became something bigger: a way to prove to myself that I could take a 1993 academic cipher specification (Schneier's original Blowfish paper) and turn it into a working, secure, real-time messaging system — including the parts most tutorials skip, like anti-replay protection, timing-safe comparisons, and authenticated encryption.

I'm sharing it because I believe the best way to learn security is to build it, break it, and fix it yourself — and I want to keep doing that at a deeper level.

---

## 📸 Demo

### Desktop — Two Windows on Same Machine

https://github.com/user-attachments/assets/896f0571-a1ec-4201-a590-5e6db6a9b7a9

> Server and client running side by side. Every message travels as Blowfish-CBC ciphertext — decrypted only on arrival.

---

### Mobile — Android Client via Pydroid 3 over WiFi

https://github.com/user-attachments/assets/f441c595-f164-4fef-b724-3e2bb731ca92

> Terminal client running on Android (Pydroid 3), connecting to the PC server over the same WiFi router. Cross-device, fully encrypted.

---

## ✨ What This Is

**Offline Secured Chat** is a peer-to-peer encrypted messaging system that works entirely over a local area network — no internet required. It demonstrates how real cryptographic protocols are built by combining multiple security primitives:

- 🔒 **Confidentiality** — Blowfish-CBC encrypts every message
- ✅ **Integrity** — HMAC-SHA256 detects any tampering
- 🔁 **Anti-replay** — Sequence numbers block replayed packets
- 🎲 **Freshness** — A new random IV is generated per message

The Blowfish algorithm is implemented **entirely from scratch in Python** — no `pycryptodome`, no `cryptography` library, no shortcuts. Every component: the key schedule, P-array, S-boxes, Feistel rounds, CBC mode, and PKCS#7 padding is hand-written and documented.

---

## 🏗️ Architecture Diagram

<img width="1670" height="940" alt="offline_secured_chat_architecture" src="https://github.com/user-attachments/assets/0f524ed2-40b5-4d96-bcf9-29e8f616aae1" />


The diagram above shows the complete message lifecycle end to end:

1. **Sender side** — plaintext is paired with a fresh random IV, encrypted with Blowfish-CBC, tagged with an HMAC over the sequence number, IV, and ciphertext, then serialized and framed for the TCP socket.
2. **Key derivation (center)** — both peers derive independent encryption and MAC keys from one pre-shared secret using SHA-256 with domain separation, so a compromise of one key never exposes the other.
3. **LAN transport** — one peer listens, the other connects; no cloud, no internet, no third-party server ever touches the traffic.
4. **Receiver side** — the packet is parsed, its version and sequence number checked, its HMAC verified in constant time, and only then decrypted back into plaintext.

*(Place the diagram image at `./assets/architecture-diagram.png` in your repository, or update the path above to match wherever you store it.)*

---

## 🏗️ How It Works

```
User A types a message
        │
        ▼
IV = os.urandom(8)              ← Fresh random IV per message
        │
        ▼
ciphertext = Blowfish_CBC(plaintext, enc_key, IV)
        │
        ▼
tag = HMAC_SHA256(mac_key, seq ║ IV ║ ciphertext)
        │
        ▼
{ version, seq, IV, ciphertext, hmac }  →  TCP socket
        │
        ▼
User B verifies HMAC → checks seq → decrypts → reads message
```

### The Security Stack

| Layer | Mechanism | Purpose |
|-------|-----------|---------|
| Encryption | Blowfish-CBC (256-bit key) | Message confidentiality |
| Authentication | HMAC-SHA256 | Tamper detection |
| Key derivation | SHA-256 with domain separation | Independent enc/mac keys |
| IV generation | `os.urandom(8)` | Prevents pattern analysis |
| Anti-replay | Strictly-increasing sequence numbers | Blocks packet replay |
| Timing safety | `hmac.compare_digest()` | Timing attack resistance |

---

## 🔬 The Blowfish Algorithm — From Scratch

Blowfish (Bruce Schneier, 1993) is a symmetric block cipher with:
- **Block size:** 64 bits (8 bytes)
- **Key length:** 32–448 bits (4–56 bytes)
- **Structure:** 16-round Feistel network

The implementation in `blowfish.py` covers every component:

```
Key Schedule
├── Initialize P-array (18 subkeys) from pi digits
├── Initialize 4 S-boxes (256 entries each) from pi digits
└── XOR key into P-array → run 521 Blowfish encryptions
    → produces fully key-dependent subkeys and S-boxes

Encryption (per 64-bit block)
├── Split into 32-bit halves (xL, xR)
├── 16 rounds:
│   ├── xL = xL XOR P[i]
│   ├── xR = F(xL) XOR xR
│   └── swap xL, xR
└── Output whitening with P[16], P[17]

F-Function
├── Split x into four 8-bit pieces: a, b, c, d
└── ((S[0][a] + S[1][b]) XOR S[2][c]) + S[3][d]

CBC Mode
├── Each block XOR'd with previous ciphertext block
├── First block XOR'd with random IV
└── Decryption reverses the chain
```

---

## 📁 Project Structure

```
offline-secured-chat/
│
├── blowfish.py                # Blowfish cipher from scratch (ECB + CBC)
├── secure_protocol.py         # Key derivation, packet framing, HMAC, anti-replay
├── server.py                  # GUI server — dark-themed tkinter (User B)
├── client.py                  # GUI client — dark-themed tkinter (User A)
├── client_mobile.py           # Single-file GUI client for Android (Pydroid 3)
├── mobile_terminal_client.py  # Zero-dependency terminal client (Termux/Pydroid)
├── test_cases.py              # 15 automated test cases
└── assets/
    └── architecture-diagram.png
```

---

## 🚀 Getting Started

### Requirements

- Python **3.10+** (tested on 3.12.2)
- No external libraries — everything uses the Python standard library
- Two devices on the **same WiFi network** (or same machine for testing)

### Run the Server (Device B)

```bash
python server.py
```

The server window opens and displays your **local IP address** in the header. Share this IP with the other user.

### Run the Client (Device A)

```bash
python client.py
```

A dialog will ask for the server's IP. Enter the IP shown in the server window.

> For same-machine testing, enter `127.0.0.1`

### Run Test Cases

```bash
python test_cases.py
```

All 15 test cases should pass.

---

## 📱 Android Support

The project includes two options for running on Android:

**Option 1 — GUI client** (`client_mobile.py`) — single self-contained file with the full Blowfish implementation and tkinter UI. Paste all files into the same Pydroid 3 folder.

**Option 2 — Terminal client** (`mobile_terminal_client.py`) — zero-dependency console app. Works in Pydroid 3, Termux, or any Python terminal. Just type and press Enter.

```
Install Pydroid 3 from Play Store
→ Open mobile_terminal_client.py
→ Tap Run
→ Enter server IP when prompted
→ Chat securely
```

---

## 🌐 Network Modes

| Setup | Server IP to enter | Notes |
|-------|--------------------|-------|
| Same machine | `127.0.0.1` | Testing only |
| PC ↔ PC (WiFi) | Server's LAN IP | Both on same router |
| PC ↔ Android (WiFi) | Server's LAN IP | Both on same router |
| Android ↔ Android | Either device's IP | Both on same router |

> **Important:** Both devices must be connected to the **same WiFi router or hotspot**. This is a LAN-only application — it does not use the internet.

---

## 🧪 Test Cases

15 automated tests validate correctness and security:

| # | Test | What It Validates |
|---|------|--------------------|
| TC-01 | Basic ECB encrypt/decrypt | Core algorithm correctness |
| TC-02 | Empty string | Edge case — zero-length input |
| TC-03 | Long message (500+ chars) | Multi-block encryption |
| TC-04 | Special chars + Unicode | UTF-8 and symbol handling |
| TC-05 | Different keys → different output | Key sensitivity |
| TC-06 | Wrong key fails to decrypt | Key uniqueness enforcement |
| TC-07 | Numeric string | Data type coverage |
| TC-08 | Urdu/Arabic Unicode | Multi-byte character support |
| TC-09 | Ciphertext type is bytes | Output type contract |
| TC-10 | Ciphertext ≠ plaintext | Encryption actually changes data |
| TC-11 | Minimum key (4 bytes) | Boundary condition |
| TC-12 | Maximum key (56 bytes) | Boundary condition |
| TC-13 | CBC mode round-trip | Mode correctness |
| TC-14 | Tampered packet rejected | HMAC integrity enforcement |
| TC-15 | Replay packet rejected | Anti-replay enforcement |

---

## 🛡️ Security Properties

| Property | Status | Implementation |
|----------|--------|-----------------|
| Confidentiality | ✅ | Blowfish-CBC, 256-bit derived key |
| Integrity | ✅ | HMAC-SHA256 per packet |
| Authenticity | ✅ | HMAC verifies correct sender key |
| Anti-replay | ✅ | Strictly-increasing sequence numbers |
| IV uniqueness | ✅ | `os.urandom(8)` per message |
| Key separation | ✅ | SHA-256 domain-separated derivation |
| Timing safety | ✅ | `hmac.compare_digest()` |

---

## 🚫 Threat Model — What This Does *Not* Protect Against

Being explicit about limitations is part of responsible security engineering. This project does **not** protect against:

- **Key compromise** — if the pre-shared key leaks, all past and future messages encrypted with it can be decrypted. There is no forward secrecy.
- **Endpoint compromise** — if either device is compromised (malware, physical access), the attacker reads plaintext directly from memory, regardless of the encryption in transit.
- **Man-in-the-middle during key exchange** — because the key is shared out-of-band (manually, by the users), the protocol itself does not authenticate that the key was exchanged safely.
- **Traffic analysis** — an observer on the LAN can see that two devices are communicating, and roughly how much data, even though they cannot read the content.
- **Denial of service** — the protocol does not defend against a flood of malformed or excessive packets.

This scope was intentional: the goal was to build and understand authenticated symmetric encryption correctly, not to solve key distribution or network-layer security, which are separate, well-studied problems.

---

## Known Limitations

- **Pre-shared key** — both users must agree on the same secret key in advance. No automated key exchange is implemented.
- **LAN only** — no NAT traversal. Internet deployment requires a relay.
- **One-to-one** — current architecture is one server, one client per session.
- **No persistence** — chat history disappears when the window closes.

---

## 💡 Where This Can Be Used

**Offline-first environments:**
Private networks where internet connectivity is unavailable or untrusted — factory floors, field operations, internal lab networks, air-gapped environments.

**Education and security research:**
A readable, documented, scratch implementation of a real cipher for learning how symmetric encryption, CBC mode, and authenticated encryption actually work at the bit level.

**LAN communication:**
Any two devices on the same network — home, office, campus — that need private, tamper-evident messaging without routing traffic through a cloud service.

**Embedded / IoT prototyping:**
Pure Python, no dependencies. Adaptable for Raspberry Pi, microcontrollers running MicroPython, or any environment with socket support.

---

## 🔮 Scope and Future Direction

This project is a working foundation. Natural extensions include:

- **Asymmetric key exchange** — Replace the pre-shared key with RSA or Diffie-Hellman so two strangers can establish a secure session without meeting first
- **Group chat** — A relay server that forwards encrypted messages between multiple clients
- **File transfer** — Encrypt and send arbitrary files over the same protocol
- **Internet support** — NAT traversal or a relay server to connect devices across different networks
- **Native mobile app** — Rebuild the client in Kotlin with Jetpack Compose for a proper Android experience
- **Persistent history** — Store encrypted conversation logs locally with SQLite

---

## 🎓 What I Learned

Building this project from scratch taught me lessons that using a library never would have:

- **Symmetric cryptography, at the bit level** — implementing the Feistel network, P-array/S-box key schedule, and F-function by hand gave me a real understanding of *why* Blowfish is secure, not just *that* it is.
- **Authenticated encryption is not optional** — encryption alone (confidentiality) does nothing to stop tampering; I learned firsthand why encrypt-then-MAC is the standard pattern, and implemented it rather than just reading about it.
- **Small details break security** — using `==` instead of `hmac.compare_digest()` for tag comparison introduces a timing side-channel; reusing an IV breaks CBC's security guarantees. Security is won or lost in details like these.
- **Protocol design beyond the cipher** — anti-replay via sequence numbers, packet framing, and version negotiation taught me that a "secure chat app" is a systems problem, not just a math problem.
- **Testing security code differently** — my 15 test cases don't just check correctness (does it decrypt correctly?) but also check *failure modes* (does it correctly reject a tampered or replayed packet?), which is a different mindset from typical functional testing.
- **Writing for other readers** — documenting the cipher clearly enough that someone else could learn from the code, not just run it, was its own exercise in communication.

---

## 🌍 Impact

- Serves as a **teaching resource**: the from-scratch Blowfish implementation is fully documented and can be used by students studying cryptography or network security to see a real cipher built line by line, rather than as a black box.
- Provides a **usable tool** for environments where internet-based chat apps are unavailable or untrusted — field teams, labs, and offline facilities can communicate securely over a local network with zero setup cost.
- Demonstrates, in a single self-contained project, the full stack of an authenticated encryption system — key derivation, encryption, integrity, and anti-replay — which is a pattern directly transferable to real-world secure systems.
- Reflects my broader goal: to pursue graduate study and research in cryptography and applied security, building on projects like this one that combine theoretical understanding with working implementation.

---

## 🏗️ Built With

| Technology | Role |
|------------|------|
| Python 3.12 | Language |
| `socket` | TCP networking |
| `tkinter` | Desktop GUI |
| `hashlib` | SHA-256 key derivation |
| `hmac` | HMAC-SHA256 authentication |
| `os.urandom` | Cryptographic IV generation |
| `struct` | Binary packet framing |
| `threading` | Concurrent send/receive |

> No external cryptographic libraries. All cipher logic is original.

---

## 📖 References

- Schneier, B. (1993). *Description of a New Variable-Length Key, 64-Bit Block Cipher (Blowfish)*. Fast Software Encryption, Cambridge Security Workshop.
- [Python `hmac` documentation](https://docs.python.org/3/library/hmac.html)
- [Python `hashlib` documentation](https://docs.python.org/3/library/hashlib.html)
- Stallings, W. *Cryptography and Network Security*, 7th Edition.

---

## 👤 About Me

> I'm a 6th-semester Computer Networking student with a strong interest in applied cryptography and systems security. This project reflects my approach to learning: understand a concept deeply enough to build it from first principles, not just use it.

> 📧 gshoaib998@gmail.com · 🔗[LinkedIn](https://www.linkedin.com/in/muhammad-shoaib-khalid)

---

## 📄 License

MIT License — free to use, modify, and distribute.
