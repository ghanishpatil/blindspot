# ARTEFACT 8 — WEAK CRYPTO TODAY (single DES)
# Single DES in ECB mode, used by the legacy PIN block translator.
#
# Added for BUILD SPEC section 9 algorithm coverage (DES). Uses pycryptodome
# rather than pyca/cryptography, since the latter exposes no single-DES
# primitive — which also proves the scanner detects across two different
# library APIs.
#
# Single DES has a 56-bit key and is exhaustively searchable. ECB mode leaks
# block equality on top of that. Both are present-day defects.
"""PIN block translation for the legacy ATM acquiring switch.

The switch speaks a 1990s-era ISO 9564 format-0 dialect. Traffic terminates
here and is re-enciphered before it reaches the modern authorisation path.
"""

from __future__ import annotations

from Crypto.Cipher import DES

PIN_BLOCK_BYTES = 8


def translate_pin_block(terminal_key: bytes, pin_block: bytes) -> bytes:
    """Decipher an inbound PIN block under the terminal's working key."""
    cipher = DES.new(terminal_key, DES.MODE_ECB)
    return cipher.decrypt(pin_block)


def reencipher_pin_block(zone_key: bytes, pin_block: bytes) -> bytes:
    """Re-encipher a PIN block under the acquirer zone key."""
    cipher = DES.new(zone_key, DES.MODE_ECB)
    return cipher.encrypt(pin_block)
