# Benchmark case: single-DES in ECB mode. Ground-truth: doubly weak.
# DES has a 56-bit key (brute-force feasible); ECB leaks block equality.
"""Legacy PIN block translator (deprecated -- do not extend)."""

from __future__ import annotations

from Crypto.Cipher import DES


def translate_pin_block(pin_block: bytes, key: bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(pin_block)
