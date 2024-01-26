#!/usr/bin/env python3

__author__ = "Evan Wilkerson"
__version__ = "0.1.0"

from typing import Type
import hmac
import struct
import math
from hashlib import _hashlib, pbkdf2_hmac, sha1, sha256, sha384


def is_utf8(byte_string: bytes) -> bool:
    """
    Check if a byte string is valid UTF-8 encoded.

    Parameters:
    - byte_string (bytes): The byte string to be checked.

    Returns:
    - bool: True if the byte string is valid UTF-8 encoded, False otherwise.

    Note:
    This function attempts to decode the given byte string using UTF-8.
    If the decoding succeeds, the byte string is considered UTF-8 encoded.
    If a `UnicodeDecodeError` occurs during decoding, the byte string is not UTF-8 encoded.
    """
    try:
        byte_string.decode('utf-8')
        return True
    except UnicodeDecodeError:
        return False


def passphrase_to_psk(passphrase: bytes, ssid: bytes) -> bytes:
    """
    Convert a passphrase and SSID to a Pre-Shared Key (PSK) using PBKDF2-HMAC-SHA1.

    Parameters:
    - passphrase (bytes): ASCII-encoded passphrase.
    - ssid (bytes): UTF-8-encoded SSID.

    Returns:
    - bytes: Pre-Shared Key (PSK) generated using PBKDF2-HMAC-SHA1.

    Raises:
    - ValueError: If the passphrase is not an ASCII encoded byte string,
                  or if the passphrase length is not between 8 and 63 bytes (characters).
    - ValueError: If the SSID is not a UTF-8 encoded byte string,
                  or if the SSID length is more than 32 characters.
    """
    if not (type(passphrase) == bytes and passphrase.isascii()):
        raise ValueError("The passphrase must be an ASCII encoded byte string.")
    if not 8 <= len(passphrase) <= 63:
        raise ValueError("Invalid passphrase length. It must be between 8 and 63 bytes (characters).")
    if not (type(ssid) == bytes and is_utf8(ssid)):
        raise ValueError("The SSID must be an UTF-8 encoded byte string.")
    if not len(ssid) <= 32:
        raise ValueError("Invalid SSID length. It must be 32 characters or less")
    try:
        psk = pbkdf2_hmac('sha1', passphrase, ssid, 4096, 256 // 8)
        return psk
    except Exception as e:
        print(f"An unexpected error has occured: {e}")


def get_pmkid(pmk: bytes, aa: bytes, spa: bytes, hash_func: Type[_hashlib.HASH]) -> tuple:
    """
    Generate PMKID (Pairwise Master Key Identifier) using the given PMK (Pairwise Master Key),
    Authenticator Address (AA), and Supplicant Address (SPA).

    Parameters:
    - pmk (bytes): Pairwise Master Key.
    - aa (bytes): Authenticator Address.
    - spa (bytes): Supplicant Address.
    - hash_func: Hash function to use for HMAC (hashlib.sha21, hashlib.sha256 or hashlib.sha384).

    Returns:
    - bytes: PMKID calculated using HMAC with the specified parameters.
    """
    try:
        PMKID_LABEL = bytes("PMK Name", "ascii")
        pmkid = hmac.new(pmk, PMKID_LABEL + aa + spa, hash_func).digest()[:16]
        return pmkid
    except Exception as e:
        print(f"An unexpected error has occured: {e}")


def getAB(anonce: bytes, snonce: bytes, aa: bytes, spa: bytes) -> tuple:
    """
    Generate values A (label) and B (context) for pairwise key expansion.

    Parameters:
    - anonce (bytes): Supplicant Nonce.
    - snonce (bytes): Authenticator Nonce.
    - aa (bytes): Authenticator Address.
    - spa (bytes): Supplicant Address.

    Returns:
    - tuple: A tuple containing values A and B.
      - bytes: Value A ('Pairwise key expansion').
      - bytes: Value B constructed by concatenating addresses and nonces.

    Note:
    The inputs (addresses and nonces) are concatenated in a specific order:
    - min(aa, spa) + max(aa, spa) + min(anonce, snonce) + max(anonce, snonce).
    """
    try:
        A = b'Pairwise key expansion'
        B = min(aa, spa) + max(aa, spa) + min(anonce, snonce) + max(anonce, snonce)
        return A, B
    except Exception as e:
        print(f"An unexpected error has occured: {e}")


def prf(K: bytes, A: bytes, B: bytes, length: int) -> bytes:
    """
    Generate pseudo-random key material using SHA-1-based Pseudo-Random Function (PRF).

    Parameters:
    - K (bytes): Key for the PRF.
    - A (bytes): Value A.
    - B (bytes): Value B.
    - length (int): Length of the desired output in bytes.

    Returns:
    - bytes: Pseudo-random key material generated using SHA-1-based PRF.

    Note:
    The input values A and B are concatenated with specific padding and iteration,
    following the formula A + chr(0) + B + chr(i), where i is the iteration count.
    """
    try:
        i = 0
        R = b''
        while i <= math.ceil((length * 8) / 160):
            hmacsha1 = hmac.new(K, A + chr(0).encode() + B + chr(i).encode(), sha1)
            R = R + hmacsha1.digest()
            i += 1
        return R[0:length]
    except Exception as e:
        print(f"An unexpected error has occured: {e}")


def kdf(K: bytes, label: bytes, context: bytes, length: int, hash_func: Type[_hashlib.HASH]) -> bytes:
    """
    Key Derivation Function (KDF) using HMAC-based Extract-and-Expand Key Derivation Function (HKDF) approach.

    Parameters:
    - K (bytes): Initial key material.
    - label (bytes): Label for the specific key derivation operation.
    - context (bytes): Context information for the key derivation.
    - length (int): Desired length of the derived key in bytes.
    - hash_func: Hash function to use for HMAC (hashlib.sha256 or hashlib.sha384).

    Returns:
    - bytes: Derived key generated using HMAC-based HKDF.

    Note:
    The HKDF approach involves iteratively applying HMAC with a specific concatenation of values,
    including the iteration count, label, context, and desired output length.
    """
    try:
        i = 1
        result = b''
        hash_size = hash_func().digest_size * 8
        while i <= math.ceil((length * 8) / hash_size):
            hmacsha256 = hmac.new(K, struct.pack('<H', i) + label + context + struct.pack('<H', (length * 8)), hash_func)
            result = result + hmacsha256.digest()
            i += 1
        return result[0:length]
    except Exception as e:
        print(f"An unexpected error has occured: {e}")