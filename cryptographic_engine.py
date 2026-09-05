#!/usr/bin/env python3

import os
import sys
import json
import base64
import hashlib
import hmac
import logging
import argparse
import getpass
import string
from datetime import datetime

# ---- Third-party dependencies ----
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from tqdm import tqdm

try:
    import pyzipper
    ZIP_SUPPORT = True
except ImportError:
    ZIP_SUPPORT = False

try:
    from PIL import Image
    STEGO_SUPPORT = True
except ImportError:
    STEGO_SUPPORT = False


# ======================================================================
# 1. CONFIGURATION & LOGGING
# ======================================================================

CONFIG_PATH = "config.json"
LOG_PATH = "crypto_engine.log"

DEFAULT_CONFIG = {
    "log_level": "INFO",
    "pbkdf2_iterations": 390000,
    "rsa_key_size": 2048,
    "output_dir": "."
}


def load_config(path: str = CONFIG_PATH) -> dict:
    """Loads config from JSON, creating a default file if missing."""
    if not os.path.exists(path):
        with open(path, "w") as f:
            json.dump(DEFAULT_CONFIG, f, indent=4)
        return DEFAULT_CONFIG.copy()
    with open(path, "r") as f:
        return json.load(f)


def setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        filename=LOG_PATH,
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )


CONFIG = load_config()
setup_logging(CONFIG.get("log_level", "INFO"))


# ======================================================================
# 2. INPUT VALIDATION HELPERS
# ======================================================================

class InputValidationError(Exception):
    """Raised whenever user-supplied input fails validation checks."""
    pass


def require_non_empty(value: str, field_name: str) -> str:
    if value is None or str(value).strip() == "":
        raise InputValidationError(f"'{field_name}' cannot be empty.")
    return value


def require_mode(mode: str) -> str:
    mode = (mode or "").strip().lower()
    if mode not in ("encrypt", "decrypt"):
        raise InputValidationError(
            f"Invalid mode '{mode}'. Expected 'encrypt' or 'decrypt'."
        )
    return mode


def require_int(value, field_name: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        raise InputValidationError(f"'{field_name}' must be a valid integer.")


def require_file_exists(path: str, field_name: str = "File") -> str:
    require_non_empty(path, field_name)
    if not os.path.isfile(path):
        raise InputValidationError(f"{field_name} '{path}' does not exist or is not a file.")
    return path


def require_alpha_key(key: str, field_name: str = "Key") -> str:
    require_non_empty(key, field_name)
    if not key.isalpha():
        raise InputValidationError(f"'{field_name}' must contain letters only.")
    return key


def require_algorithm(algorithm: str, allowed: tuple, field_name: str = "Algorithm") -> str:
    algorithm = (algorithm or "").strip().lower()
    if algorithm not in allowed:
        raise InputValidationError(
            f"Invalid {field_name.lower()} '{algorithm}'. Allowed values: {', '.join(allowed)}."
        )
    return algorithm


# ======================================================================
# 3. CLASSICAL CIPHERS (Educational)
# ======================================================================

def caesar_cipher(text: str, shift: int, mode: str = "encrypt") -> str:
    """Encrypts or decrypts text using Caesar Cipher (modular arithmetic).

    Raises:
        InputValidationError: if text is empty, shift is not an integer,
                               or mode is not 'encrypt'/'decrypt'.
    """
    require_non_empty(text, "Text")
    shift = require_int(shift, "Shift")
    mode = require_mode(mode)

    if mode == "decrypt":
        shift = -shift
    result = []
    for char in text:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            new_char = chr((ord(char) - start + shift) % 26 + start)
            result.append(new_char)
        else:
            result.append(char)
    return "".join(result)


def caesar_brute_force(ciphertext: str) -> list:
    """Returns all 25 possible Caesar decryptions for manual inspection."""
    require_non_empty(ciphertext, "Ciphertext")
    return [(shift, caesar_cipher(ciphertext, shift, mode="decrypt")) for shift in range(1, 26)]


def vigenere_cipher(text: str, key: str, mode: str = "encrypt") -> str:
    """Encrypts/decrypts text using the Vigenere cipher (poly-alphabetic).

    Raises:
        InputValidationError: if text/key is empty, key has non-letters,
                               or mode is invalid.
    """
    require_non_empty(text, "Text")
    require_alpha_key(key, "Vigenere key")
    mode = require_mode(mode)
    key = key.lower()
    result = []
    key_index = 0
    for char in text:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_index % len(key)]) - ord('a')
            if mode == "decrypt":
                shift = -shift
            new_char = chr((ord(char) - start + shift) % 26 + start)
            result.append(new_char)
            key_index += 1
        else:
            result.append(char)
    return "".join(result)


# ======================================================================
# 3. LEGACY XOR CIPHER (kept for backward compatibility)
# ======================================================================

def xor_symmetric_cipher(data: bytes, key: str) -> bytes:
    """Encrypts/Decrypts byte stream using XOR with a repeating key stream."""
    if not data:
        raise InputValidationError("Data cannot be empty.")
    require_non_empty(key, "Key")
    key_bytes = key.encode('utf-8')
    return bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data)])


# ======================================================================
# 4. KEY DERIVATION & SALT GENERATION
# ======================================================================

def generate_salt(length: int = 16) -> bytes:
    return os.urandom(length)


def derive_key(password: str, salt: bytes, iterations: int = None) -> bytes:
    """Derives a 32-byte Fernet-compatible key from a password using PBKDF2-HMAC-SHA256."""
    require_non_empty(password, "Password")
    iterations = iterations or CONFIG.get("pbkdf2_iterations", 390000)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))


# ======================================================================
# 5. AES (FERNET) SYMMETRIC ENCRYPTION
# ======================================================================

def aes_encrypt_text(plaintext: str, password: str) -> str:
    """Encrypts text with AES (Fernet), embedding the salt in the output."""
    require_non_empty(plaintext, "Text")
    require_non_empty(password, "Password")
    salt = generate_salt()
    key = derive_key(password, salt)
    token = Fernet(key).encrypt(plaintext.encode('utf-8'))
    payload = base64.urlsafe_b64encode(salt + b"::" + token).decode('utf-8')
    logging.info("AES text encryption performed.")
    return payload


def aes_decrypt_text(payload: str, password: str) -> str:
    """Decrypts text previously encrypted with aes_encrypt_text."""
    require_non_empty(payload, "Encrypted payload")
    require_non_empty(password, "Password")
    try:
        raw = base64.urlsafe_b64decode(payload.encode('utf-8'))
        salt, token = raw.split(b"::", 1)
    except Exception:
        raise InputValidationError("Encrypted payload is malformed or corrupted.")
    key = derive_key(password, salt)
    try:
        plaintext = Fernet(key).decrypt(token)
    except InvalidToken:
        raise ValueError("Decryption failed: wrong password or corrupted data.")
    logging.info("AES text decryption performed.")
    return plaintext.decode('utf-8')


def aes_encrypt_file(file_path: str, password: str, show_progress: bool = True) -> str:
    """Encrypts a file using AES (Fernet) with a password-derived key."""
    require_file_exists(file_path, "File")
    require_non_empty(password, "Password")

    salt = generate_salt()
    key = derive_key(password, salt)
    fernet = Fernet(key)

    with open(file_path, "rb") as f:
        data = f.read()

    chunk_size = 1024 * 1024
    chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)] or [b""]
    encrypted_chunks = []
    iterator = tqdm(chunks, desc="Encrypting", unit="chunk") if show_progress else chunks
    for chunk in iterator:
        encrypted_chunks.append(fernet.encrypt(chunk))

    enc_path = file_path + ".aes"
    with open(enc_path, "wb") as f:
        f.write(salt + b"\n")
        for c in encrypted_chunks:
            f.write(base64.b64encode(c) + b"\n")

    logging.info(f"File encrypted: {file_path} -> {enc_path}")
    return enc_path


def aes_decrypt_file(file_path: str, password: str, show_progress: bool = True) -> str:
    """Decrypts a file produced by aes_encrypt_file."""
    require_file_exists(file_path, "Encrypted file")
    require_non_empty(password, "Password")

    with open(file_path, "rb") as f:
        lines = f.read().split(b"\n")

    if not lines or not lines[0]:
        raise InputValidationError("File does not appear to be a valid encrypted file.")

    salt = lines[0]
    key = derive_key(password, salt)
    fernet = Fernet(key)

    dec_path = file_path.replace(".aes", "") + ".dec"
    iterator = tqdm(lines[1:], desc="Decrypting", unit="chunk") if show_progress else lines[1:]
    with open(dec_path, "wb") as out:
        for line in iterator:
            if not line:
                continue
            try:
                out.write(fernet.decrypt(base64.b64decode(line)))
            except InvalidToken:
                raise ValueError("Decryption failed: wrong password or corrupted file.")

    logging.info(f"File decrypted: {file_path} -> {dec_path}")
    return dec_path


def aes_batch_encrypt(file_paths: list, password: str) -> list:
    """Encrypts multiple files in one operation."""
    if not file_paths:
        raise InputValidationError("At least one file path must be provided.")
    require_non_empty(password, "Password")
    results = []
    for path in tqdm(file_paths, desc="Batch encrypting", unit="file"):
        try:
            results.append(aes_encrypt_file(path, password, show_progress=False))
        except Exception as e:
            logging.error(f"Batch encryption failed for {path}: {e}")
            results.append(f"[!] Failed: {path} ({e})")
    return results


# ======================================================================
# 6. RSA ASYMMETRIC ENCRYPTION & DIGITAL SIGNATURES
# ======================================================================

def rsa_generate_keypair(key_size: int = None, out_dir: str = "."):
    """Generates an RSA keypair and saves PEM files to disk."""
    key_size = key_size or CONFIG.get("rsa_key_size", 2048)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()

    priv_path = os.path.join(out_dir, "rsa_private.pem")
    pub_path = os.path.join(out_dir, "rsa_public.pem")

    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(pub_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    logging.info("RSA keypair generated.")
    return priv_path, pub_path


def rsa_encrypt(message: str, public_key_path: str) -> str:
    require_non_empty(message, "Message")
    require_file_exists(public_key_path, "Public key file")
    try:
        with open(public_key_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
    except Exception:
        raise InputValidationError(f"'{public_key_path}' is not a valid RSA public key file.")
    ciphertext = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )
    return base64.b64encode(ciphertext).decode('utf-8')


def rsa_decrypt(ciphertext_b64: str, private_key_path: str) -> str:
    require_non_empty(ciphertext_b64, "Ciphertext")
    require_file_exists(private_key_path, "Private key file")
    try:
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    except Exception:
        raise InputValidationError(f"'{private_key_path}' is not a valid RSA private key file.")
    try:
        ciphertext = base64.b64decode(ciphertext_b64, validate=True)
    except Exception:
        raise InputValidationError("Ciphertext is not valid Base64.")
    try:
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None)
        )
    except Exception:
        raise ValueError("Decryption failed: wrong key or corrupted ciphertext.")
    return plaintext.decode('utf-8')


def rsa_sign(message: str, private_key_path: str) -> str:
    """Creates a digital signature for a message."""
    require_non_empty(message, "Message")
    require_file_exists(private_key_path, "Private key file")
    try:
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    except Exception:
        raise InputValidationError(f"'{private_key_path}' is not a valid RSA private key file.")
    signature = private_key.sign(
        message.encode('utf-8'),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')


def rsa_verify(message: str, signature_b64: str, public_key_path: str) -> bool:
    """Verifies a digital signature. Returns True/False (no exception on failure)."""
    require_non_empty(message, "Message")
    require_non_empty(signature_b64, "Signature")
    require_file_exists(public_key_path, "Public key file")
    try:
        with open(public_key_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
    except Exception:
        raise InputValidationError(f"'{public_key_path}' is not a valid RSA public key file.")
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except Exception:
        raise InputValidationError("Signature is not valid Base64.")
    try:
        public_key.verify(
            signature, message.encode('utf-8'),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# ======================================================================
# 7. HASHING & INTEGRITY VERIFICATION
# ======================================================================

def compute_hash(data: bytes, algorithm: str = "sha256") -> str:
    if not data:
        raise InputValidationError("Data to hash cannot be empty.")
    algorithm = require_algorithm(algorithm, ("md5", "sha256", "sha512"), "Algorithm")
    h = hashlib.new(algorithm)
    h.update(data)
    return h.hexdigest()


def hash_file(file_path: str, algorithm: str = "sha256") -> str:
    require_file_exists(file_path, "File")
    with open(file_path, "rb") as f:
        return compute_hash(f.read(), algorithm)


def hmac_sign(data: bytes, key: str, algorithm: str = "sha256") -> str:
    """Generates an HMAC for integrity/authenticity verification."""
    if not data:
        raise InputValidationError("Data cannot be empty.")
    require_non_empty(key, "HMAC key")
    algorithm = require_algorithm(algorithm, ("md5", "sha256", "sha512"), "Algorithm")
    return hmac.new(key.encode('utf-8'), data, getattr(hashlib, algorithm)).hexdigest()


def hmac_verify(data: bytes, key: str, expected_hmac: str, algorithm: str = "sha256") -> bool:
    require_non_empty(expected_hmac, "Expected HMAC")
    computed = hmac_sign(data, key, algorithm)
    return hmac.compare_digest(computed, expected_hmac)


# ======================================================================
# 8. ENCODING UTILITIES
# ======================================================================

def encode_base64(text: str) -> str:
    require_non_empty(text, "Text")
    return base64.b64encode(text.encode('utf-8')).decode('utf-8')


def decode_base64(text: str) -> str:
    require_non_empty(text, "Text")
    try:
        return base64.b64decode(text.encode('utf-8'), validate=True).decode('utf-8')
    except Exception:
        raise InputValidationError("Input is not valid Base64-encoded text.")


def encode_hex(text: str) -> str:
    require_non_empty(text, "Text")
    return text.encode('utf-8').hex()


def decode_hex(text: str) -> str:
    require_non_empty(text, "Text")
    try:
        return bytes.fromhex(text).decode('utf-8')
    except Exception:
        raise InputValidationError("Input is not valid hex-encoded text.")


# ======================================================================
# 9. PASSWORD STRENGTH CHECKER (basic integration)
# ======================================================================

def check_password_strength(password: str) -> dict:
    """Basic NIST-inspired password strength assessment."""
    require_non_empty(password, "Password")
    length_ok = len(password) >= 12
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in string.punctuation for c in password)

    score = sum([length_ok, has_upper, has_lower, has_digit, has_symbol])
    verdict = {5: "Strong", 4: "Good", 3: "Moderate", 2: "Weak"}.get(score, "Very Weak")

    return {
        "length_ok": length_ok,
        "has_upper": has_upper,
        "has_lower": has_lower,
        "has_digit": has_digit,
        "has_symbol": has_symbol,
        "score": f"{score}/5",
        "verdict": verdict
    }


# ======================================================================
# 10. STEGANOGRAPHY (LSB - Least Significant Bit)
# ======================================================================

DELIMITER = "1111111111111110"  # marks end of hidden message


def _text_to_bits(text: str) -> str:
    return ''.join(format(byte, '08b') for byte in text.encode('utf-8'))


def _bits_to_text(bits: str) -> str:
    byte_chunks = [bits[i:i + 8] for i in range(0, len(bits), 8)]
    byte_arr = bytearray(int(b, 2) for b in byte_chunks)
    return byte_arr.decode('utf-8', errors='ignore')


def stego_hide_text(image_path: str, message: str, output_path: str) -> str:
    """Hides a text message inside an image using LSB steganography."""
    if not STEGO_SUPPORT:
        raise RuntimeError("Pillow is required for steganography features.")
    require_file_exists(image_path, "Source image")
    require_non_empty(message, "Message")
    require_non_empty(output_path, "Output path")
    try:
        img = Image.open(image_path).convert("RGB")
    except Exception:
        raise InputValidationError(f"'{image_path}' is not a valid image file.")
    bits = _text_to_bits(message) + DELIMITER
    pixels = list(img.getdata())

    if len(bits) > len(pixels) * 3:
        raise InputValidationError("Message too long to hide in this image.")

    new_pixels = []
    bit_idx = 0
    for pixel in pixels:
        pixel = list(pixel)
        for ch in range(3):
            if bit_idx < len(bits):
                pixel[ch] = (pixel[ch] & ~1) | int(bits[bit_idx])
                bit_idx += 1
        new_pixels.append(tuple(pixel))

    img.putdata(new_pixels)
    img.save(output_path)
    logging.info(f"Steganography: message hidden in {output_path}")
    return output_path


def stego_extract_text(image_path: str) -> str:
    """Extracts a hidden text message from an image."""
    if not STEGO_SUPPORT:
        raise RuntimeError("Pillow is required for steganography features.")
    require_file_exists(image_path, "Image")
    try:
        img = Image.open(image_path).convert("RGB")
    except Exception:
        raise InputValidationError(f"'{image_path}' is not a valid image file.")
    bits = ""
    for pixel in img.getdata():
        for ch in range(3):
            bits += str(pixel[ch] & 1)
            if bits.endswith(DELIMITER):
                return _bits_to_text(bits[:-len(DELIMITER)])
    return _bits_to_text(bits)


# ======================================================================
# 11. PASSWORD-PROTECTED ZIP ARCHIVES
# ======================================================================

def create_encrypted_zip(file_paths: list, password: str, output_zip: str) -> str:
    if not ZIP_SUPPORT:
        raise RuntimeError("pyzipper is required for encrypted ZIP features.")
    if not file_paths:
        raise InputValidationError("At least one file path must be provided.")
    for p in file_paths:
        require_file_exists(p, "File")
    require_non_empty(password, "ZIP password")
    require_non_empty(output_zip, "Output ZIP path")
    with pyzipper.AESZipFile(output_zip, 'w', compression=pyzipper.ZIP_LZMA,
                              encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(password.encode('utf-8'))
        for path in file_paths:
            zf.write(path, arcname=os.path.basename(path))
    logging.info(f"Encrypted ZIP created: {output_zip}")
    return output_zip


def extract_encrypted_zip(zip_path: str, password: str, extract_dir: str = ".") -> list:
    if not ZIP_SUPPORT:
        raise RuntimeError("pyzipper is required for encrypted ZIP features.")
    require_file_exists(zip_path, "ZIP file")
    require_non_empty(password, "ZIP password")
    try:
        with pyzipper.AESZipFile(zip_path) as zf:
            zf.setpassword(password.encode('utf-8'))
            zf.extractall(path=extract_dir)
            names = zf.namelist()
    except RuntimeError:
        raise ValueError("Extraction failed: wrong password.")
    except Exception:
        raise InputValidationError(f"'{zip_path}' is not a valid encrypted ZIP file.")
    logging.info(f"Encrypted ZIP extracted: {zip_path}")
    return names


# ======================================================================
# 12. INTERACTIVE CLI MENU
# ======================================================================

def interactive_menu():
    print("=" * 66)
    print("     DECODELABS CYBER SECURITY: CRYPTOGRAPHY ENGINE (v2.0)      ")
    print("=" * 66)

    menu = """
 1.  Caesar Cipher (encrypt/decrypt)
 2.  Caesar Cipher Brute-Force
 3.  Vigenere Cipher (encrypt/decrypt)
 4.  Legacy XOR Cipher (string)
 5.  AES Encrypt Text (password-based)
 6.  AES Decrypt Text (password-based)
 7.  AES Encrypt File
 8.  AES Decrypt File
 9.  AES Batch Encrypt Files
 10. Generate RSA Keypair
 11. RSA Encrypt Message
 12. RSA Decrypt Message
 13. RSA Sign Message
 14. RSA Verify Signature
 15. Hash Text / File (MD5/SHA256/SHA512)
 16. HMAC Sign / Verify Data
 17. Base64 Encode/Decode
 18. Hex Encode/Decode
 19. Password Strength Checker
 20. Steganography - Hide Text in Image
 21. Steganography - Extract Text from Image
 22. Create Password-Protected ZIP
 23. Extract Password-Protected ZIP
 0.  Exit
"""

    while True:
        print(menu)
        choice = input("Enter choice: ").strip()

        try:
            if choice == "1":
                mode = input("Mode (encrypt/decrypt): ").strip().lower()
                text = input("Text: ")
                shift_raw = input("Shift (integer): ").strip()
                shift = require_int(shift_raw, "Shift")
                print("Result:", caesar_cipher(text, shift, mode))

            elif choice == "2":
                text = input("Ciphertext: ")
                for shift, guess in caesar_brute_force(text):
                    print(f"  Shift {shift:>2}: {guess}")

            elif choice == "3":
                mode = input("Mode (encrypt/decrypt): ").strip().lower()
                text = input("Text: ")
                key = input("Key (letters only): ")
                print("Result:", vigenere_cipher(text, key, mode))

            elif choice == "4":
                text = input("Text: ")
                key = input("Key: ")
                enc = xor_symmetric_cipher(text.encode('utf-8'), key)
                print("Result (Base64):", base64.b64encode(enc).decode('utf-8'))

            elif choice == "5":
                text = input("Text: ")
                pw = getpass.getpass("Password: ")
                print("Encrypted payload:", aes_encrypt_text(text, pw))

            elif choice == "6":
                payload = input("Encrypted payload: ")
                pw = getpass.getpass("Password: ")
                print("Decrypted text:", aes_decrypt_text(payload, pw))

            elif choice == "7":
                path = input("File path: ").strip()
                pw = getpass.getpass("Password: ")
                print("Saved to:", aes_encrypt_file(path, pw))

            elif choice == "8":
                path = input("Encrypted (.aes) file path: ").strip()
                pw = getpass.getpass("Password: ")
                print("Saved to:", aes_decrypt_file(path, pw))

            elif choice == "9":
                paths = input("File paths (comma-separated): ").split(",")
                paths = [p.strip() for p in paths if p.strip()]
                pw = getpass.getpass("Password: ")
                for r in aes_batch_encrypt(paths, pw):
                    print(" ", r)

            elif choice == "10":
                out_dir = input("Output directory [.]: ").strip() or "."
                priv, pub = rsa_generate_keypair(out_dir=out_dir)
                print("Private key:", priv)
                print("Public key :", pub)

            elif choice == "11":
                msg = input("Message: ")
                pub_path = input("Public key path: ").strip()
                print("Ciphertext (Base64):", rsa_encrypt(msg, pub_path))

            elif choice == "12":
                ct = input("Ciphertext (Base64): ").strip()
                priv_path = input("Private key path: ").strip()
                print("Plaintext:", rsa_decrypt(ct, priv_path))

            elif choice == "13":
                msg = input("Message: ")
                priv_path = input("Private key path: ").strip()
                print("Signature (Base64):", rsa_sign(msg, priv_path))

            elif choice == "14":
                msg = input("Message: ")
                sig = input("Signature (Base64): ").strip()
                pub_path = input("Public key path: ").strip()
                print("Valid:", rsa_verify(msg, sig, pub_path))

            elif choice == "15":
                src = input("Hash (t)ext or (f)ile? ").strip().lower()
                algo = input("Algorithm (md5/sha256/sha512): ").strip().lower()
                if src == "f":
                    path = input("File path: ").strip()
                    print("Hash:", hash_file(path, algo))
                else:
                    text = input("Text: ")
                    print("Hash:", compute_hash(text.encode('utf-8'), algo))

            elif choice == "16":
                action = input("(s)ign or (v)erify? ").strip().lower()
                text = input("Text: ")
                key = input("HMAC key: ")
                if action == "v":
                    expected = input("Expected HMAC: ").strip()
                    print("Valid:", hmac_verify(text.encode('utf-8'), key, expected))
                else:
                    print("HMAC:", hmac_sign(text.encode('utf-8'), key))

            elif choice == "17":
                action = input("(e)ncode or (d)ecode? ").strip().lower()
                text = input("Text: ")
                print("Result:", encode_base64(text) if action == "e" else decode_base64(text))

            elif choice == "18":
                action = input("(e)ncode or (d)ecode? ").strip().lower()
                text = input("Text: ")
                print("Result:", encode_hex(text) if action == "e" else decode_hex(text))

            elif choice == "19":
                pw = getpass.getpass("Password to check: ")
                for k, v in check_password_strength(pw).items():
                    print(f"  {k}: {v}")

            elif choice == "20":
                img = input("Source image path: ").strip()
                msg = input("Message to hide: ")
                out = input("Output image path: ").strip()
                print("Saved to:", stego_hide_text(img, msg, out))

            elif choice == "21":
                img = input("Image path: ").strip()
                print("Hidden message:", stego_extract_text(img))

            elif choice == "22":
                paths = input("File paths (comma-separated): ").split(",")
                paths = [p.strip() for p in paths if p.strip()]
                pw = getpass.getpass("ZIP password: ")
                out = input("Output ZIP path: ").strip()
                print("Created:", create_encrypted_zip(paths, pw, out))

            elif choice == "23":
                zip_path = input("ZIP path: ").strip()
                pw = getpass.getpass("ZIP password: ")
                out_dir = input("Extract to [.]: ").strip() or "."
                print("Extracted:", extract_encrypted_zip(zip_path, pw, out_dir))

            elif choice == "0":
                print("\nExiting Cryptography Engine. Keep your keys safe!")
                break

            else:
                print("[!] Invalid option.")

        except InputValidationError as e:
            logging.warning(f"Invalid input on menu choice {choice}: {e}")
            print(f"[!] Invalid input: {e}")

        except (ValueError, FileNotFoundError, RuntimeError) as e:
            logging.error(f"Operation failed on menu choice {choice}: {e}")
            print(f"[!] Error: {e}")

        except Exception as e:
            logging.error(f"Unexpected error on menu choice {choice}: {e}")
            print(f"[!] Unexpected error: {e}")


# ======================================================================
# 13. ARGPARSE CLI (non-interactive mode)
# ======================================================================

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="DecodeLabs Cryptography Engine - CLI mode"
    )
    sub = parser.add_subparsers(dest="command")

    p_hash = sub.add_parser("hash", help="Hash text or a file")
    p_hash.add_argument("--text", help="Text to hash")
    p_hash.add_argument("--file", help="File to hash")
    p_hash.add_argument("--algo", default="sha256", choices=["md5", "sha256", "sha512"])

    p_aesenc = sub.add_parser("aes-encrypt-file", help="AES-encrypt a file")
    p_aesenc.add_argument("path")
    p_aesenc.add_argument("--password", required=True)

    p_aesdec = sub.add_parser("aes-decrypt-file", help="AES-decrypt a file")
    p_aesdec.add_argument("path")
    p_aesdec.add_argument("--password", required=True)

    p_rsa = sub.add_parser("rsa-genkey", help="Generate an RSA keypair")
    p_rsa.add_argument("--out-dir", default=".")

    return parser


def run_cli(args) -> bool:
    """Handles argparse-based invocation. Returns True if a command was run."""
    try:
        if args.command == "hash":
            if args.file:
                print(hash_file(args.file, args.algo))
            elif args.text:
                print(compute_hash(args.text.encode('utf-8'), args.algo))
            else:
                print("[!] Invalid input: provide --text or --file")
            return True

        elif args.command == "aes-encrypt-file":
            print(aes_encrypt_file(args.path, args.password))
            return True

        elif args.command == "aes-decrypt-file":
            print(aes_decrypt_file(args.path, args.password))
            return True

        elif args.command == "rsa-genkey":
            priv, pub = rsa_generate_keypair(out_dir=args.out_dir)
            print(f"Private: {priv}\nPublic : {pub}")
            return True

    except InputValidationError as e:
        logging.warning(f"CLI invalid input ({args.command}): {e}")
        print(f"[!] Invalid input: {e}")
        return True

    except (ValueError, FileNotFoundError, RuntimeError) as e:
        logging.error(f"CLI operation failed ({args.command}): {e}")
        print(f"[!] Error: {e}")
        return True

    except Exception as e:
        logging.error(f"CLI unexpected error ({args.command}): {e}")
        print(f"[!] Unexpected error: {e}")
        return True

    return False


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.command:
        run_cli(args)
    else:
        interactive_menu()


if __name__ == "__main__":
    main()
