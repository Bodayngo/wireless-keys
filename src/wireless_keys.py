import math
import hmac
import struct
from hashlib import pbkdf2_hmac, sha1, sha256, sha384


def passphrase_to_psk(passphrase: bytes, ssid: bytes) -> bytes:
    try:
        psk = pbkdf2_hmac('sha1', passphrase, ssid, 4096, 256 // 8)
        return psk
    except Exception as e:
        print(f"An unexpected error has occured: {e}")


def _pmkid(pmk: bytes, aa: bytes, spa: bytes, hash_func) -> bytes:
    try:
        PMKID_LABEL = bytes("PMK Name", "ascii")
        pmkid = hmac.new(pmk, PMKID_LABEL + aa + spa, hash_func).digest()[:16]
        return pmkid
    except Exception as e:
        print(f"An unexpected error has occurred: {e}")


def pmkid_sha1(pmk: bytes, aa: bytes, spa: bytes) -> bytes:
    return _pmkid(pmk, aa, spa, sha1)


def pmkid_sha256(pmk: bytes, aa: bytes, spa: bytes) -> bytes:
    return _pmkid(pmk, aa, spa, sha256)


def pmkid_sha384(pmk: bytes, aa: bytes, spa: bytes) -> bytes:
    return _pmkid(pmk, aa, spa, sha384)


def getAB(anonce: bytes, snonce: bytes, aa: bytes, spa: bytes) -> tuple:
    try:
        A = b'Pairwise key expansion'
        B = min(aa, spa) + max(aa, spa) + min(anonce, snonce) + max(anonce, snonce)
        return A, B
    except Exception as e:
        print(f"An unexpected error has occured: {e}")


def prf_sha1(K: bytes, A: bytes, B: bytes, length: int) -> bytes:
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
    return _kdf(K, label, context, length, sha256)


def kdf_sha384(K: bytes, label: bytes, context: bytes, length: int) -> bytes:
    return _kdf(K, label, context, length, sha384)