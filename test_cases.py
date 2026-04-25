# test_cases.py
# Test Cases for Blowfish Algorithm Implementation
# Project: Offline Secured Chat Application
# Student: Muhammad Shoaib Khalid

from blowfish import BlowfishCipher
from secure_protocol import build_secure_packet, derive_keys, parse_secure_packet
import os

PASS = "✅ PASS"
FAIL = "❌ FAIL"

def run_test(test_name, result, expected):
    status = PASS if result == expected else FAIL
    print(f"{status} | {test_name}")
    if result != expected:
        print(f"       Expected : {expected}")
        print(f"       Got      : {result}")

def test_basic_encrypt_decrypt():
    """TC-01: Basic message encrypt then decrypt returns original."""
    cipher = BlowfishCipher(b"TestKey1")
    msg = "Hello, World!"
    encrypted = cipher.encrypt_message(msg)
    decrypted = cipher.decrypt_message(encrypted)
    run_test("TC-01: Basic encrypt/decrypt", decrypted, msg)

def test_empty_string():
    """TC-02: Empty string encrypt/decrypt."""
    cipher = BlowfishCipher(b"TestKey1")
    msg = ""
    encrypted = cipher.encrypt_message(msg)
    decrypted = cipher.decrypt_message(encrypted)
    run_test("TC-02: Empty string", decrypted, msg)

def test_long_message():
    """TC-03: Long message (paragraph)."""
    cipher = BlowfishCipher(b"LongKeyTest99")
    msg = "This is a very long message used to test the Blowfish algorithm with multiple blocks of data to ensure correctness across block boundaries."
    encrypted = cipher.encrypt_message(msg)
    decrypted = cipher.decrypt_message(encrypted)
    run_test("TC-03: Long message", decrypted, msg)

def test_special_characters():
    """TC-04: Special characters and symbols."""
    cipher = BlowfishCipher(b"SpecialKey!")
    msg = "Hello! @#$%^&*() 123 — test."
    encrypted = cipher.encrypt_message(msg)
    decrypted = cipher.decrypt_message(encrypted)
    run_test("TC-04: Special characters", decrypted, msg)

def test_different_keys_different_output():
    """TC-05: Same message with different keys produces different ciphertext."""
    msg = "SameMessage"
    cipher1 = BlowfishCipher(b"KeyOne123")
    cipher2 = BlowfishCipher(b"KeyTwo456")
    enc1 = cipher1.encrypt_message(msg)
    enc2 = cipher2.encrypt_message(msg)
    result = enc1 != enc2
    run_test("TC-05: Different keys → different ciphertext", result, True)

def test_wrong_key_cannot_decrypt_correctly():
    """TC-06: Wrong key produces garbage (not original message)."""
    cipher1 = BlowfishCipher(b"CorrectKey1")
    cipher2 = BlowfishCipher(b"WrongKey999")
    msg = "Secret message"
    encrypted = cipher1.encrypt_message(msg)
    try:
        decrypted = cipher2.decrypt_message(encrypted)
        result = decrypted != msg
    except Exception:
        result = True  # Exception also means wrong key can't decrypt
    run_test("TC-06: Wrong key cannot decrypt", result, True)

def test_numeric_message():
    """TC-07: Numeric string message."""
    cipher = BlowfishCipher(b"NumericKey1")
    msg = "1234567890"
    encrypted = cipher.encrypt_message(msg)
    decrypted = cipher.decrypt_message(encrypted)
    run_test("TC-07: Numeric string", decrypted, msg)

def test_urdu_unicode():
    """TC-08: Unicode / Urdu characters."""
    cipher = BlowfishCipher(b"UnicodeKey1")
    msg = "ہیلو دنیا"  # "Hello World" in Urdu
    encrypted = cipher.encrypt_message(msg)
    decrypted = cipher.decrypt_message(encrypted)
    run_test("TC-08: Unicode/Urdu characters", decrypted, msg)

def test_ciphertext_is_bytes():
    """TC-09: Encrypted output should be bytes, not string."""
    cipher = BlowfishCipher(b"ByteCheck1")
    msg = "Check type"
    encrypted = cipher.encrypt_message(msg)
    run_test("TC-09: Ciphertext is bytes", isinstance(encrypted, bytes), True)

def test_ciphertext_not_equal_plaintext():
    """TC-10: Ciphertext should not equal original plaintext bytes."""
    cipher = BlowfishCipher(b"NotEqualKey")
    msg = "PlainText"
    encrypted = cipher.encrypt_message(msg)
    run_test("TC-10: Ciphertext ≠ plaintext", encrypted != msg.encode(), True)

def test_minimum_key_length():
    """TC-11: Minimum key length (4 bytes) works."""
    cipher = BlowfishCipher(b"Keys")  # exactly 4 bytes
    msg = "MinKey"
    encrypted = cipher.encrypt_message(msg)
    decrypted = cipher.decrypt_message(encrypted)
    run_test("TC-11: Minimum key (4 bytes)", decrypted, msg)

def test_maximum_key_length():
    """TC-12: Maximum key length (56 bytes) works."""
    key = b"A" * 56  # exactly 56 bytes
    cipher = BlowfishCipher(key)
    msg = "MaxKey"
    encrypted = cipher.encrypt_message(msg)
    decrypted = cipher.decrypt_message(encrypted)
    run_test("TC-12: Maximum key (56 bytes)", decrypted, msg)

def test_cbc_mode_roundtrip():
    """TC-13: CBC mode encrypt/decrypt roundtrip."""
    cipher = BlowfishCipher(b"CBCModeKey77")
    msg = "CBC mode test message"
    iv = os.urandom(8)
    encrypted = cipher.encrypt_message_cbc(msg, iv)
    decrypted = cipher.decrypt_message_cbc(encrypted, iv)
    run_test("TC-13: CBC mode roundtrip", decrypted, msg)

def test_secure_packet_tamper_detected():
    """TC-14: HMAC tampering should be detected."""
    enc_key, mac_key = derive_keys(b"SharedSecret123")
    cipher = BlowfishCipher(enc_key)
    packet = build_secure_packet(cipher, mac_key, "Integrity check", 1)

    tampered = dict(packet)
    tampered["ciphertext"] = tampered["ciphertext"][:-2] + "AA"

    try:
        parse_secure_packet(cipher, mac_key, tampered, 0)
        result = False
    except Exception:
        result = True

    run_test("TC-14: Tampered packet rejected", result, True)


if __name__ == "__main__":
    print("=" * 55)
    print("  Blowfish Algorithm Test Cases")
    print("  Project: Offline Secured Chat Application")
    print("=" * 55)

    test_basic_encrypt_decrypt()
    test_empty_string()
    test_long_message()
    test_special_characters()
    test_different_keys_different_output()
    test_wrong_key_cannot_decrypt_correctly()
    test_numeric_message()
    test_urdu_unicode()
    test_ciphertext_is_bytes()
    test_ciphertext_not_equal_plaintext()
    test_minimum_key_length()
    test_maximum_key_length()
    test_cbc_mode_roundtrip()
    test_secure_packet_tamper_detected()

    print("=" * 55)
    print("  All test cases completed.")
    print("=" * 55)