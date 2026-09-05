"""
Unit tests for cryptographic_engine.py
Run with: pytest -v test_cryptographic_engine.py
"""

import pytest
import cryptographic_engine as c


# ----------------------------------------------------------------------
# Valid-input (happy path) tests
# ----------------------------------------------------------------------

def test_caesar_roundtrip():
    original = "Hello, World!"
    enc = c.caesar_cipher(original, 5, "encrypt")
    dec = c.caesar_cipher(enc, 5, "decrypt")
    assert dec == original
    assert enc != original


def test_caesar_brute_force_contains_correct_shift():
    original = "attackatdawn"
    enc = c.caesar_cipher(original, 7, "encrypt")
    results = dict(c.caesar_brute_force(enc))
    assert results[7] == original


def test_vigenere_roundtrip():
    original = "AttackAtDawn"
    enc = c.vigenere_cipher(original, "lemon", "encrypt")
    dec = c.vigenere_cipher(enc, "lemon", "decrypt")
    assert dec == original


def test_xor_symmetric_roundtrip():
    data = b"Secret data"
    key = "mykey"
    enc = c.xor_symmetric_cipher(data, key)
    dec = c.xor_symmetric_cipher(enc, key)
    assert dec == data


def test_aes_text_roundtrip():
    payload = c.aes_encrypt_text("Confidential", "P@ssw0rd123!")
    assert c.aes_decrypt_text(payload, "P@ssw0rd123!") == "Confidential"


def test_aes_file_roundtrip(tmp_path):
    file_path = tmp_path / "sample.txt"
    file_path.write_text("Top secret file content")
    enc_path = c.aes_encrypt_file(str(file_path), "filepass123", show_progress=False)
    dec_path = c.aes_decrypt_file(enc_path, "filepass123", show_progress=False)
    with open(dec_path, "r") as f:
        assert f.read() == "Top secret file content"


def test_hash_functions():
    data = b"hello world"
    assert len(c.compute_hash(data, "md5")) == 32
    assert len(c.compute_hash(data, "sha256")) == 64
    assert len(c.compute_hash(data, "sha512")) == 128


def test_hmac_sign_and_verify():
    data = b"important data"
    key = "secretkey"
    signature = c.hmac_sign(data, key)
    assert c.hmac_verify(data, key, signature) is True
    assert c.hmac_verify(b"tampered data", key, signature) is False


def test_base64_roundtrip():
    assert c.decode_base64(c.encode_base64("Hello Pakistan!")) == "Hello Pakistan!"


def test_hex_roundtrip():
    assert c.decode_hex(c.encode_hex("Cybersecurity")) == "Cybersecurity"


def test_password_strength_checker_strong():
    result = c.check_password_strength("Str0ng!Passw0rd")
    assert result["verdict"] == "Strong"


def test_rsa_encrypt_decrypt_roundtrip(tmp_path):
    priv, pub = c.rsa_generate_keypair(out_dir=str(tmp_path))
    message = "RSA test message"
    ciphertext = c.rsa_encrypt(message, pub)
    assert c.rsa_decrypt(ciphertext, priv) == message


def test_rsa_sign_and_verify(tmp_path):
    priv, pub = c.rsa_generate_keypair(out_dir=str(tmp_path))
    message = "Sign this message"
    signature = c.rsa_sign(message, priv)
    assert c.rsa_verify(message, signature, pub) is True
    assert c.rsa_verify("Tampered message", signature, pub) is False


# ----------------------------------------------------------------------
# Invalid-input tests — these must raise InputValidationError, not crash
# ----------------------------------------------------------------------

def test_caesar_empty_text_raises():
    with pytest.raises(c.InputValidationError):
        c.caesar_cipher("", 3, "encrypt")


def test_caesar_invalid_shift_raises():
    with pytest.raises(c.InputValidationError):
        c.caesar_cipher("hello", "abc", "encrypt")


def test_caesar_invalid_mode_raises():
    with pytest.raises(c.InputValidationError):
        c.caesar_cipher("hello", 3, "scramble")


def test_vigenere_non_alpha_key_raises():
    with pytest.raises(c.InputValidationError):
        c.vigenere_cipher("test", "key123", "encrypt")


def test_vigenere_empty_text_raises():
    with pytest.raises(c.InputValidationError):
        c.vigenere_cipher("", "lemon", "encrypt")


def test_xor_empty_key_raises():
    with pytest.raises(c.InputValidationError):
        c.xor_symmetric_cipher(b"data", "")


def test_aes_encrypt_text_empty_password_raises():
    with pytest.raises(c.InputValidationError):
        c.aes_encrypt_text("Secret", "")


def test_aes_decrypt_text_malformed_payload_raises():
    with pytest.raises(c.InputValidationError):
        c.aes_decrypt_text("not-a-valid-payload", "password")


def test_aes_text_wrong_password_raises_value_error():
    payload = c.aes_encrypt_text("Confidential", "correct-password")
    with pytest.raises(ValueError):
        c.aes_decrypt_text(payload, "wrong-password")


def test_aes_encrypt_file_missing_file_raises():
    with pytest.raises(c.InputValidationError):
        c.aes_encrypt_file("/no/such/file.txt", "password")


def test_hash_invalid_algorithm_raises():
    with pytest.raises(c.InputValidationError):
        c.compute_hash(b"data", "sha1024")


def test_hash_empty_data_raises():
    with pytest.raises(c.InputValidationError):
        c.compute_hash(b"", "sha256")


def test_hash_file_missing_file_raises():
    with pytest.raises(c.InputValidationError):
        c.hash_file("/no/such/file.txt")


def test_hmac_empty_key_raises():
    with pytest.raises(c.InputValidationError):
        c.hmac_sign(b"data", "")


def test_base64_decode_invalid_raises():
    with pytest.raises(c.InputValidationError):
        c.decode_base64("not valid base64 !!!")


def test_hex_decode_invalid_raises():
    with pytest.raises(c.InputValidationError):
        c.decode_hex("zzz-not-hex")


def test_password_strength_empty_raises():
    with pytest.raises(c.InputValidationError):
        c.check_password_strength("")


def test_rsa_encrypt_missing_key_file_raises():
    with pytest.raises(c.InputValidationError):
        c.rsa_encrypt("message", "/no/such/key.pem")


def test_rsa_encrypt_empty_message_raises():
    with pytest.raises(c.InputValidationError):
        c.rsa_encrypt("", "/no/such/key.pem")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
