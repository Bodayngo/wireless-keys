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
import hmac
from hashlib import sha1
from src.wireless_keys import passphrase_to_psk, pmkid_sha1, getAB, prf_sha1

ssid = bytes('Josh_Test', 'ascii')
passphrase = bytes('SuperSecretPassword', 'utf-8')
client_mac = bytes.fromhex('8abf72d72d17')
bssid = bytes.fromhex('8e468d31adad')
anonce = bytes.fromhex('575e45d3fe2e8953be82f4245392061e9a24b896338937e593d68b38ac672617')
snonce = bytes.fromhex('7bf4614ebfee7660e336c09f1a03ae21cc9e5919e3ca7519f6ed732923e8927e')

# 802.1X contents with MIC field zeroed out "00000000000000000000000000000000"
message1 = bytes.fromhex("0203005f02008a00100000000000000001575e45d3fe2e8953be82f4245392061e9a24b896338937e593d68b38ac6726170000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
message2 = bytes.fromhex("0203007502010a001000000000000000017bf4614ebfee7660e336c09f1a03ae21cc9e5919e3ca7519f6ed732923e8927e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac040100000fac040100000fac020c00")
message3 = bytes.fromhex("020300970213ca00100000000000000002575e45d3fe2e8953be82f4245392061e9a24b896338937e593d68b38ac672617000000000000000000000000000000002a00000000000000000000000000000000000000000000000000000000000000003802981105505e3a959d147c512c99ddaa719aafa4dcadbb6f3d0066d3db9ddf4d2aaa3272a0e2826f9c80c227ccdddfab85b5c6ae7fdbc478")
message4 = bytes.fromhex("0203005f02030a0010000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")

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

    data = [message2, message3, message4]
    
    
    mics = [hmac.new(kck, i, sha1).digest() for i in data]

    print(mics[0].hex()[:-8])
    print(mics[1].hex()[:-8])
    print(mics[2].hex()[:-8])


if __name__ == "__main__":
    main()