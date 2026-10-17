import os
import time

from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
    ChaCha20Poly1305,
)


def encrypt_message(message, algorithm):
    plaintext = message.encode("utf-8")

    key = os.urandom(32)
    nonce = os.urandom(12)

    if algorithm == "AES-256-GCM":
        cipher = AESGCM(key)

    elif algorithm == "ChaCha20-Poly1305":
        cipher = ChaCha20Poly1305(key)

    else:
        raise ValueError("Unsupported encryption algorithm")

    start_time = time.perf_counter()

    ciphertext = cipher.encrypt(
        nonce,
        plaintext,
        None,
    )

    encryption_time = time.perf_counter() - start_time

    return {
        "algorithm": algorithm,
        "key": key,
        "nonce": nonce,
        "ciphertext": ciphertext,
        "encryption_time": encryption_time,
    }


def decrypt_message(encrypted_data):
    algorithm = encrypted_data["algorithm"]
    key = encrypted_data["key"]
    nonce = encrypted_data["nonce"]
    ciphertext = encrypted_data["ciphertext"]

    if algorithm == "AES-256-GCM":
        cipher = AESGCM(key)

    elif algorithm == "ChaCha20-Poly1305":
        cipher = ChaCha20Poly1305(key)

    else:
        raise ValueError("Unsupported encryption algorithm")

    start_time = time.perf_counter()

    plaintext = cipher.decrypt(
        nonce,
        ciphertext,
        None,
    )

    decryption_time = time.perf_counter() - start_time

    return plaintext.decode("utf-8"), decryption_time