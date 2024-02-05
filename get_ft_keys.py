from src.wireless_keys import *
import hashlib

client_mac = bytes.fromhex('8045dd31c4c8')
ap_mac = bytes.fromhex('c29c2ee79b80')
msk = bytes.fromhex('8ac5d963ab3cbaf0918e8eee8ddedb911616f5fdee981685a5927937550ed2b50b9affcfb4bfa1279c63775c53ec31cc200921e1950612a9d86c00cb2dcbc66b')
ssid = b'Bodayngo-Test'
mdid = bytes.fromhex('674b')
r0khid = bytes.fromhex('43432d39432d33452d45372d39422d38303a76617033')
r1khid = bytes.fromhex('cc9c3ee79b80')
anonce = bytes.fromhex('5d50f961dbe204591caeee869458e4d4617e80453dfa7df24fd65d83ee662a4f')
snonce = bytes.fromhex('380f2fc769e21357f9c591a9eaccb4e3cef5e651d538857dd9fc507211836154')

def get_dot1X_pmkid(msk, aa, spa):
    """
    12.7.1.3 Pairwise key hierarchy
        PMKID = Truncate-128(HMAC-SHA-1(PMK, “PMK Name” || AA || SPA))
    """
    pmk = msk[0:32]
    pmkid = pmkid_sha1(pmk, aa, spa)
    return pmkid

def get_pmkr0(msk, aa, spa, ssid, mdid, r0khid, s0khid):
    """
    12.7.1.6.3 PMK-R0
        If the negotiated AKM is 00-0F-AC:3, then Q = 256 and
            - MPMK = L(MSK, 256, 256), i.e., the second 256 bits of the MSK
            - PMKID = Truncate-128(HMAC-SHA-256(MPMK, “PMK Name” || AA || SPA))

        R0-Key-Data = KDF-Hash-Length(XXKey, “FT-R0”, SSIDlength || SSID || MDID || R0KHlength || R0KH-ID || S0KH-ID)
        PMK-R0 = L(R0-Key-Data, 0, Q)
        PMK-R0Name-Salt = L(R0-Key-Data, Q, 128)
        Length = Q + 128
    """
    mpmk = msk[32:64]
    pmkid = pmkid_sha256(mpmk, aa, spa)

    ssid_len = chr(len(ssid)).encode()
    r0khid_len = chr(len(r0khid)).encode()
    
    r0_key_data = kdf_sha256(mpmk, b'FT-R0', ssid_len + ssid + mdid + r0khid_len + r0khid + s0khid, 48)
    pmk_r0 = r0_key_data[0:32]
    pmk_r0_name_salt = r0_key_data[32:48]
    pmk_r0_name = hashlib.sha256(b'FT-R0N' + pmk_r0_name_salt).digest()[0:16]
    
    return pmkid, pmk_r0, pmk_r0_name


def get_pmkr1(pmk_r0, pmk_r0_name, r1khid, s1khid):
    """
    12.7.1.6.4 PMK-R1
        PMK-R1 = KDF-Hash-Length(PMK-R0, “FT-R1”, R1KH-ID || S1KH-ID)
        PMKR1Name = Truncate-128(Hash(“FT-R1N” || PMKR0Name || R1KH-ID || S1KH-ID))
    """
    pmk_r1 = kdf_sha256(pmk_r0, b'FT-R1', r1khid + s1khid, 32)
    pmk_r1_name = hashlib.sha256(b'FT-R1N' + pmk_r0_name + r1khid + s1khid).digest()[0:16]

    return pmk_r1, pmk_r1_name

def get_ptk(pmk_r1, pmk_r1_name, snonce, anonce, bssid, sta_addr):
    """
    12.7.1.6.5 PTK
        PTK = KDF-Hash-Length(PMK-R1, “FT-PTK”, SNonce || ANonce || BSSID || STA-ADDR)
        PTKName = Truncate-128(SHA-256(PMKR1Name || “FT-PTKN” || SNonce || ANonce || BSSID || STA-ADDR))
    """
    ptk = kdf_sha256(pmk_r1, b'FT-PTK', snonce + anonce + bssid + sta_addr, 48)
    ptk_name = hashlib.sha256(pmk_r1_name + b'FT-PTKN' + snonce + anonce + bssid + sta_addr).digest()[0:16]

    return ptk, ptk_name


def main():
    # 802.1X PMKID
    dot1x_pmkid = get_dot1X_pmkid(msk, ap_mac, client_mac)
    print(f"802.1X PMKID: {dot1x_pmkid.hex()}")
    print()

    # PMK-R0
    mpmk_pmkid, pmk_r0, pmk_r0_name = get_pmkr0(msk, ap_mac, client_mac, ssid, mdid, r0khid, client_mac)
    print(f"MPMK PMKID:   {mpmk_pmkid.hex()}")
    print(f"PMK-R0:       {pmk_r0.hex()}")
    print(f"PMKR0Name:    {pmk_r0_name.hex()}")
    print()

    # PMK-R1
    pmk_r1, pmk_r1_name = get_pmkr1(pmk_r0, pmk_r0_name, r1khid, client_mac)
    print(f"PMK-R1:     {pmk_r1.hex()}")
    print(f"PMKR1Name:  {pmk_r1_name.hex()}")
    print()

    # PTK
    ptk, ptk_name = get_ptk(pmk_r1, pmk_r1_name, snonce, anonce, ap_mac, client_mac)
    kck = ptk[0:16]
    kek = ptk[16:32]
    tk = ptk[32:48]
    print(f"KCK:        {kck.hex()}")
    print(f"KEK:        {kek.hex()}")
    print(f"TK:         {tk.hex()}")
    print(f"PTKName:    {ptk_name.hex()}")


if __name__ == "__main__":
    main()