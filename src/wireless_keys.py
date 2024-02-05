import math
import hmac
import struct
from hashlib import pbkdf2_hmac, sha1, sha256, sha384


def passphrase_to_psk(passphrase: bytes, ssid: bytes) -> bytes:
    """
    Derives a Pre-Shared Key (PSK) from a passphrase and SSID using PBKDF2-HMAC-SHA1.

    Args:
        passphrase (bytes): The passphrase as bytes.
        ssid (bytes): The SSID as bytes.

    Returns:
        bytes: The derived PSK.
    """
    try:
        psk = pbkdf2_hmac('sha1', passphrase, ssid, 4096, 256 // 8)
        return psk
    except Exception as e:
        print(f"An unexpected error has occured: {e}")


def _pmkid(pmk: bytes, aa: bytes, spa: bytes, hash_func) -> bytes:
    """
    Computes the PMKID using HMAC with a specified hash function.

    Args:
        pmk (bytes): The Pairwise Master Key.
        aa (bytes): The Authenticator Address.
        spa (bytes): The Supplicant Address.
        hash_func: The hash function to use.

    Returns:
        bytes: The computed PMKID.

    Notes:
        Do not import/use directly. Use pmkid_sha1, pmkid_sha256, 
        or pmkid_sha384 instead.
    """
    try:
        PMKID_LABEL = bytes("PMK Name", "ascii")
        pmkid = hmac.new(pmk, PMKID_LABEL + aa + spa, hash_func).digest()[:16]
        return pmkid
    except Exception as e:
        print(f"An unexpected error has occurred: {e}")


def pmkid_sha1(pmk: bytes, aa: bytes, spa: bytes) -> bytes:
    """
    Computes the PMKID using HMAC-SHA1.

    Args:
        pmk (bytes): The Pairwise Master Key.
        aa (bytes): The Authenticator Address.
        spa (bytes): The Supplicant Address.

    Returns:
        bytes: The computed PMKID.
    """
    return _pmkid(pmk, aa, spa, sha1)


def pmkid_sha256(pmk: bytes, aa: bytes, spa: bytes) -> bytes:
    """
    Computes the PMKID using HMAC-SHA256.

    Args:
        pmk (bytes): The Pairwise Master Key.
        aa (bytes): The Authenticator Address.
        spa (bytes): The Supplicant Address.

    Returns:
        bytes: The computed PMKID.
    """
    return _pmkid(pmk, aa, spa, sha256)


def pmkid_sha384(pmk: bytes, aa: bytes, spa: bytes) -> bytes:
    """
    Computes the PMKID using HMAC-SHA384.

    Args:
        pmk (bytes): The Pairwise Master Key.
        aa (bytes): The Authenticator Address.
        spa (bytes): The Supplicant Address.

    Returns:
        bytes: The computed PMKID.
    """
    return _pmkid(pmk, aa, spa, sha384)


def getAB(anonce: bytes, snonce: bytes, aa: bytes, spa: bytes) -> tuple:
    """
    Concatenates and returns values A and B for key derivation.

    Args:
        anonce (bytes): The Authenticator Nonce.
        snonce (bytes): The Supplicant Nonce.
        aa (bytes): The Authenticator Address.
        spa (bytes): The Supplicant Address.

    Returns:
        tuple: A tuple containing values A and B.
    """
    try:
        A = b'Pairwise key expansion'
        B = min(aa, spa) + max(aa, spa) + min(anonce, snonce) + max(anonce, snonce)
        return A, B
    except Exception as e:
        print(f"An unexpected error has occured: {e}")


def prf_sha1(K: bytes, A: bytes, B: bytes, length: int) -> bytes:
    """
    Computes a pseudo-random function (PRF) using HMAC-SHA1.

    Args:
        K (bytes): The key for the PRF.
        A (bytes): Value A for the PRF.
        B (bytes): Value B for the PRF.
        length (int): The desired length of the output, in bytes.

    Returns:
        bytes: The computed PRF output.
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


def _kdf(K: bytes, label: bytes, context: bytes, length: int, hash_func) -> bytes:
    """
    Key Derivation Function (KDF) using HMAC with a specified hash function.

    Args:
        K (bytes): The key for the KDF.
        label (bytes): The label for the KDF.
        context (bytes): The context for the KDF.
        length (int): The desired length of the output, in bytes.
        hash_func: The hash function to use.

    Returns:
        bytes: The computed KDF output.
    """
    try:
        i = 1
        result = b''
        hash_length = hash_func().digest_size * 8
        while i <= math.ceil((length * 8) / hash_length):
            hash = hmac.new(K, struct.pack('<H', i) + label + context + struct.pack('<H', (length * 8)), hash_func)
            result = result + hash.digest()
            i += 1
        return result[0:length]
    except Exception as e:
        print(f"An unexpected error has occured: {e}")


def kdf_sha256(K: bytes, label: bytes, context: bytes, length: int) -> bytes:
    """
    Key Derivation Function (KDF) using HMAC-SHA256.

    Args:
        K (bytes): The key for the KDF.
        label (bytes): The label for the KDF.
        context (bytes): The context for the KDF.
        length (int): The desired length of the output, in bytes.

    Returns:
        bytes: The computed KDF output.
    """
    return _kdf(K, label, context, length, sha256)


def kdf_sha384(K: bytes, label: bytes, context: bytes, length: int) -> bytes:
    """
    Key Derivation Function (KDF) using HMAC-SHA384.

    Args:
        K (bytes): The key for the KDF.
        label (bytes): The label for the KDF.
        context (bytes): The context for the KDF.
        length (int): The desired length of the output, in bytes.

    Returns:
        bytes: The computed KDF output.
    """
    return _kdf(K, label, context, length, sha384)
