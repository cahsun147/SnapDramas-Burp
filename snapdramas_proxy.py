#!/usr/bin/env python3
"""SnapDramas proxy helper.

Minimal standalone proxy helper for decrypting/encrypting the SnapDramas
payload format.

Encryption profile recovered from the app:
- AES/ECB/PKCS5Padding
- Base64 wrapper
- static key: ipB7OHxAmJ9Qa1Lf38X1bP71zJMe4Yw6

This script is intentionally lightweight so it can be adapted to Burp, mitmproxy,
or a simple local debugging workflow.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

KEY = b"ipB7OHxAmJ9Qa1Lf38X1bP71zJMe4Yw6"
BLOCK_SIZE = 16


@dataclass
class CryptoResult:
    plaintext: str
    ciphertext_b64: str


def _clean_b64(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9+/=]", "", value).strip()


def encrypt_text(plaintext: str) -> str:
    if plaintext is None:
        raise ValueError("plaintext is required")
    cipher = AES.new(KEY, AES.MODE_ECB)
    raw = plaintext.encode("utf-8")
    encrypted = cipher.encrypt(pad(raw, BLOCK_SIZE))
    return base64.b64encode(encrypted).decode("utf-8")


def decrypt_text(ciphertext_b64: str) -> str:
    if ciphertext_b64 is None:
        raise ValueError("ciphertext is required")
    cipher = AES.new(KEY, AES.MODE_ECB)
    cleaned = _clean_b64(ciphertext_b64)
    raw = base64.b64decode(cleaned)
    decrypted = unpad(cipher.decrypt(raw), BLOCK_SIZE)
    return decrypted.decode("utf-8")


def decrypt_envelope(body: str) -> str:
    """Decrypt either a bare Base64 string or a JSON envelope with data."""
    if body is None:
        return ""
    body = body.strip()
    if not body:
        return ""

    # Common app shape: {"data":"<base64-aes>"}
    if body.startswith("{"):
        try:
            obj = json.loads(body)
            if isinstance(obj, dict) and "data" in obj and isinstance(obj["data"], str):
                return decrypt_text(obj["data"])
        except Exception:
            pass

    return decrypt_text(body)


def encrypt_envelope(plaintext: str) -> str:
    ciphertext = encrypt_text(plaintext)
    return json.dumps({"data": ciphertext}, ensure_ascii=False, separators=(",", ":"))


def transform_request_body(raw_body: str) -> CryptoResult:
    plain = decrypt_envelope(raw_body)
    return CryptoResult(plaintext=plain, ciphertext_b64=encrypt_text(plain))


def transform_response_body(raw_body: str) -> CryptoResult:
    plain = decrypt_envelope(raw_body)
    return CryptoResult(plaintext=plain, ciphertext_b64=encrypt_text(plain))


class SnapDramasProxyHelper:
    """Helper class that can be reused from Burp or local scripts."""

    def decrypt_request(self, body: str) -> str:
        return decrypt_envelope(body)

    def decrypt_response(self, body: str) -> str:
        return decrypt_envelope(body)

    def encrypt_request(self, plaintext: str) -> str:
        return encrypt_envelope(plaintext)

    def encrypt_response(self, plaintext: str) -> str:
        return encrypt_envelope(plaintext)


if __name__ == "__main__":
    sample_plain = '{"pageNum":1,"pageSize":20,"sort":2,"subtitleLang":"id"}'
    sample_cipher = encrypt_text(sample_plain)
    print("Plaintext:")
    print(sample_plain)
    print("\nCiphertext (Base64):")
    print(sample_cipher)
    print("\nRound-trip decrypted:")
    print(decrypt_text(sample_cipher))
