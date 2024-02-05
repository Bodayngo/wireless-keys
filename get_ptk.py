"""
AKM: 2 (PSK)
Pairwise Cipher: 4 (CCMP-128)

Table 12-10 — Integrity and key wrap algorithms
    KCK_bits = 128 (16 bytes)
    KEK_bits = 128 (16 bytes)
Table 12-7 — Cipher suite key lengths
    TK_bits = 128 (16 bytes)

PTK_length = KCK_bits + KEK_bits + TK_bits
    384 bits (48 bytes)
"""

from src.wireless_keys import passphrase_to_psk, pmkid_sha1, getAB, prf_sha1

ssid = bytes('Bodayngo-Test', 'ascii')
passphrase = bytes('password', 'utf-8')
client_mac = bytes.fromhex('8045dd31c4c8')
bssid = bytes.fromhex('c29c2ee79b80')
anonce = bytes.fromhex('ea868844fcadcba7495ce15c74fdbff7b81decd9050203e7236161e253be4818')
snonce = bytes.fromhex('04fe1a207ed73048afdf90bcf7c8aee7b9ea81f76de766d71a94b98a1b203c94')


def main():
    pmk = passphrase_to_psk(passphrase, ssid)
    print(f"PMK:   {pmk.hex()}")

    pmkid = pmkid_sha1(pmk, bssid, client_mac)
    print(f"PMKID: {pmkid.hex()}")

    A, B = getAB(anonce, snonce, bssid, client_mac)

    ptk = prf_sha1(pmk, A, B, 48)
    kck = ptk[0:16]
    kek = ptk[16:32]
    tk = ptk [32:48]

    print(f"PTK:   {ptk.hex()}")
    print(f"KCK:   {kck.hex()}")
    print(f"KEK:   {kek.hex()}")
    print(f"TK:    {tk.hex()}")


if __name__ == "__main__":
    main()