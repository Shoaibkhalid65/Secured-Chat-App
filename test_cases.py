# test_cases.py
# Test Cases for Blowfish Algorithm + Secure Protocol
# Project : Offline Secured Chat Application
# Name  : Jawad Khalid  |  Roll number: F25BINCE1M04090
# Course  : CSDF-30109 Information Security

import os
from blowfish import BlowfishCipher
from secure_protocol import build_secure_packet, derive_keys, parse_secure_packet

PASS = "✅ PASS"
FAIL = "❌ FAIL"


def run_test(name: str, result, expected):
    ok = result == expected
    print(f"{'✅ PASS' if ok else '❌ FAIL'}  |  {name}")
    if not ok:
        print(f"         Expected : {expected!r}")
        print(f"         Got      : {result!r}")
    return ok


# ─── Blowfish Core Tests ───────────────────────────────────────────────────────

def tc01_basic_ecb():
    c = BlowfishCipher(b"TestKey1234")
    msg = "Hello, Blowfish!"
    assert c.decrypt_message(c.encrypt_message(msg)) == msg
    run_test("TC-01  Basic ECB encrypt → decrypt", c.decrypt_message(c.encrypt_message(msg)), msg)

def tc02_empty_string():
    c = BlowfishCipher(b"TestKey1234")
    run_test("TC-02  Empty string ECB", c.decrypt_message(c.encrypt_message("")), "")

def tc03_long_message():
    c = BlowfishCipher(b"LongKeyTest99!")
    msg = "A" * 500 + " end of message."
    run_test("TC-03  Long message (500+ chars)", c.decrypt_message(c.encrypt_message(msg)), msg)

def tc04_special_chars():
    c = BlowfishCipher(b"SpecialKey!@#")
    msg = "Hello! @#$%^&*() 123 — اردو test. 你好"
    run_test("TC-04  Special chars + Unicode", c.decrypt_message(c.encrypt_message(msg)), msg)

def tc05_different_keys_diff_output():
    c1 = BlowfishCipher(b"KeyAlpha1234")
    c2 = BlowfishCipher(b"KeyBeta5678!")
    msg = "SameMessage"
    run_test("TC-05  Different keys → different ciphertext", c1.encrypt_message(msg) != c2.encrypt_message(msg), True)

def tc06_wrong_key_cannot_decrypt():
    c1 = BlowfishCipher(b"CorrectKeyABC")
    c2 = BlowfishCipher(b"WrongKey99999")
    msg = "Top Secret"
    ct  = c1.encrypt_message(msg)
    try:
        bad = c2.decrypt_message(ct)
        run_test("TC-06  Wrong key cannot decrypt", bad != msg, True)
    except Exception:
        run_test("TC-06  Wrong key cannot decrypt", True, True)

def tc07_numeric_message():
    c = BlowfishCipher(b"NumericKey123")
    msg = "0123456789"
    run_test("TC-07  Numeric string", c.decrypt_message(c.encrypt_message(msg)), msg)

def tc08_urdu_unicode():
    c = BlowfishCipher(b"UnicodeKeyUrdu")
    msg = "ہیلو دنیا — Hello World in Urdu"
    run_test("TC-08  Urdu / Unicode characters", c.decrypt_message(c.encrypt_message(msg)), msg)

def tc09_ciphertext_is_bytes():
    c = BlowfishCipher(b"ByteCheck9999")
    run_test("TC-09  Ciphertext type is bytes", isinstance(c.encrypt_message("Test"), bytes), True)

def tc10_ciphertext_ne_plaintext():
    c = BlowfishCipher(b"NotEqualKey12")
    msg = "PlainTextHere"
    run_test("TC-10  Ciphertext ≠ plaintext bytes", c.encrypt_message(msg) != msg.encode(), True)

def tc11_min_key():
    c = BlowfishCipher(b"Keys")   # 4 bytes — minimum
    msg = "MinKeyTest"
    run_test("TC-11  Minimum key length (4 bytes)", c.decrypt_message(c.encrypt_message(msg)), msg)

def tc12_max_key():
    c = BlowfishCipher(b"K" * 56)  # 56 bytes — maximum
    msg = "MaxKeyTest"
    run_test("TC-12  Maximum key length (56 bytes)", c.decrypt_message(c.encrypt_message(msg)), msg)

def tc13_cbc_roundtrip():
    c  = BlowfishCipher(b"CBCModeKey9876")
    iv = os.urandom(8)
    msg = "CBC mode round-trip test message!"
    run_test("TC-13  CBC mode encrypt → decrypt", c.decrypt_message_cbc(c.encrypt_message_cbc(msg, iv), iv), msg)

def tc14_tamper_detected():
    enc_key, mac_key = derive_keys(b"SharedSecret999")
    c = BlowfishCipher(enc_key)
    pkt = build_secure_packet(c, mac_key, "Integrity check!", 1)
    # Flip the last 2 bytes of ciphertext
    tampered = dict(pkt)
    import base64
    ct = base64.b64decode(tampered["ciphertext"])
    ct = ct[:-1] + bytes([(ct[-1] ^ 0xFF)])
    tampered["ciphertext"] = base64.b64encode(ct).decode()
    try:
        parse_secure_packet(c, mac_key, tampered, 0)
        run_test("TC-14  Tampered packet rejected", False, True)
    except ValueError:
        run_test("TC-14  Tampered packet rejected", True, True)

def tc15_replay_rejected():
    enc_key, mac_key = derive_keys(b"SharedSecret999")
    c = BlowfishCipher(enc_key)
    pkt = build_secure_packet(c, mac_key, "Original message", 5)
    try:
        parse_secure_packet(c, mac_key, pkt, 5)   # last_seq == seq → replay
        run_test("TC-15  Replay packet rejected", False, True)
    except ValueError:
        run_test("TC-15  Replay packet rejected", True, True)


# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    SEP = "─" * 60
    print(SEP)
    print("  Offline Secured Chat — Test Suite")
    print("  Algorithm : Blowfish-CBC + HMAC-SHA256")
    print("  Author    : Muhammad Shoaib Khalid")
    print(SEP)

    tc01_basic_ecb()
    tc02_empty_string()
    tc03_long_message()
    tc04_special_chars()
    tc05_different_keys_diff_output()
    tc06_wrong_key_cannot_decrypt()
    tc07_numeric_message()
    tc08_urdu_unicode()
    tc09_ciphertext_is_bytes()
    tc10_ciphertext_ne_plaintext()
    tc11_min_key()
    tc12_max_key()
    tc13_cbc_roundtrip()
    tc14_tamper_detected()
    tc15_replay_rejected()

    print(SEP)
    print("  All test cases executed.")
    print(SEP)