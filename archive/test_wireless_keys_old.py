#!/usr/bin/env python3
"""
python3 -m unittest tests/test_wireless_keys.py
"""

import unittest
from wireless_keys_old import *
import hashlib


class TestWirelessKeysFunctions(unittest.TestCase):


    def test_passphrase_to_psk(self):
        ssid = bytes('IEEE', 'ascii')
        passphrase = bytes('password', 'utf-8')

        psk = passphrase_to_psk(passphrase, ssid)

        self.assertIsInstance(psk, bytes)
        self.assertEqual(len(psk), 32)
        self.assertEqual(psk.hex(), 'f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e')


    def test_get_pmkids(self):
        pmk = bytes.fromhex('03304a03fb68e904d47b78429d661f8bc7f373f5de6df640e9b0f3e142a6fe5d')
        spa = bytes.fromhex('8045dd31c4c8')
        aa = bytes.fromhex('aa468d005020')

        pmkid_sha1 = get_pmkid(pmk, aa, spa, sha1)
        self.assertIsInstance(pmkid_sha1, bytes)
        self.assertEqual(len(pmkid_sha1), 16)
        self.assertEqual(pmkid_sha1.hex(), '0db738755972d6a09cfadc3e235c9e29')

        pmkid_sha256 = get_pmkid(pmk, aa, spa, sha256)
        self.assertIsInstance(pmkid_sha256, bytes)
        self.assertEqual(len(pmkid_sha256), 16)
        self.assertEqual(pmkid_sha256.hex(), '61eac9970bd64e1ca7820bfe9355b61b')

        pmkid_sha384  = get_pmkid(pmk, aa, spa, sha384)
        self.assertIsInstance(pmkid_sha384, bytes)
        self.assertEqual(len(pmkid_sha384), 16)
        self.assertEqual(pmkid_sha384.hex(), '5c819340218a382d62959ae0d2ecb554')


    def test_prf(self):
        sha1_prf_pmk = bytes.fromhex('8b470d911a0428b393a8396d3e0faa69d994d87f682d293c460f8262a5cbbcb1')
        sha1_prf_anonce = bytes.fromhex('13474349c681499192f7f6581121b8e60c166925fac52cc29e5d03d5a1e4acf3')
        sha1_prf_snonce = bytes.fromhex('5d13d1569b435213f9724003655882a4d6d713a894ecd00db13ce46d8f11e960')
        sha1_prf_spa = bytes.fromhex('2429348bb466')
        sha1_prf_aa = bytes.fromhex('c29c2ee79b80')

        A, B = getAB(sha1_prf_anonce, sha1_prf_snonce, sha1_prf_aa, sha1_prf_spa)
        ptk = prf(sha1_prf_pmk, A, B, 48)
        kck = ptk[0:16]
        kek = ptk[16:32]
        tk = ptk[32:48]

        self.assertIsInstance(ptk, bytes)
        self.assertEqual(len(ptk), 48)
        self.assertEqual(len(kck), 16)
        self.assertEqual(len(kek), 16)
        self.assertEqual(len(tk), 16)
        self.assertEqual(kck.hex(), '0c18b0dfda634acd02ff19138b6018dd')
        self.assertEqual(kek.hex(), '4fc9280a6833fdd9dde5c302222c2fc4')
        self.assertEqual(tk.hex(), 'ac3c0c7e2ba97c718cc5dde645e672ea')


    def test_kdf_sha256(self):
        sha256_kdf_pmk = bytes.fromhex('bf9721e26479f2a412dee0e89a4fef1894c3feceab36d53c6583ce96e3c7b2e5')
        sha256_kdf_anonce = bytes.fromhex('5417cde51869ebc00200d6ac2e43ea4d774de9aadceb438383beaf696f1601e3')
        sha256_kdf_snonce = bytes.fromhex('27d0029a0464fdac4c1870740d138c504be995a4e384a5a826ee539a2df5fe7f')
        sha256_kdf_aa = bytes.fromhex('c29c2ee79b80')
        sha256_kdf_spa = bytes.fromhex('8045dd31c4c8')

        A, B = getAB(sha256_kdf_anonce, sha256_kdf_snonce, sha256_kdf_aa, sha256_kdf_spa)
        ptk = kdf(sha256_kdf_pmk, A, B, 48, hashlib.sha256)
        kck = ptk[0:16]
        kek = ptk[16:32]
        tk = ptk[32:48]

        self.assertIsInstance(ptk, bytes)
        self.assertEqual(len(ptk), 48)
        self.assertEqual(len(kck), 16)
        self.assertEqual(len(kek), 16)
        self.assertEqual(len(tk), 16)
        self.assertEqual(kck.hex(), '9464f0b1681cb18863edcb0eef087ad8')
        self.assertEqual(kek.hex(), '206e1a8bfa66ad7f0fd9a63b7b3e31df')
        self.assertEqual(tk.hex(), 'ec7e2f6ef92b17c9df75007b8a4d437f')


    def test_kdf_sha384(self):
        sha384_kdf_pmk = bytes.fromhex('8bf26829f546c3bb66890da1fc7b0f7e3863f70a41abccd50c735fbc090863fa61639bbb3dd616c3172d068cc0188edd')
        sha384_kdf_anonce = bytes.fromhex('5c4d0eb6835565c3dc7ee4f8f36193282041a27faf9dc8dbbbc7f16eee627cd0')
        sha384_kdf_snonce = bytes.fromhex('1ec0830d02bc8a70044ea182a12b88605fcc58495b233092fa8ba119fb94c388')
        sha384_kdf_aa = bytes.fromhex('c29c2ee79b80')
        sha384_kdf_spa = bytes.fromhex('8045dd31c4c8')

        A, B = getAB(sha384_kdf_anonce, sha384_kdf_snonce, sha384_kdf_aa, sha384_kdf_spa)
        ptk = kdf(sha384_kdf_pmk, A, B, 88, hashlib.sha384)
        kck = ptk[0:24]
        kek = ptk[24:56]
        tk = ptk[56:88]
    
        self.assertIsInstance(ptk, bytes)
        self.assertEqual(len(ptk), 88)
        self.assertEqual(len(kck), 24)
        self.assertEqual(len(kek), 32)
        self.assertEqual(len(tk), 32)
        self.assertEqual(kck.hex(), '2c7aaab3991bd283ba0d5bf830206010eeed382c945c9301')
        self.assertEqual(kek.hex(), 'b6ea093b60f94f90ae11f26a0f2ba4a2fa10f0ad9a8fd26657ca5b5e1348f0f0')
        self.assertEqual(tk.hex(), '7091d35e275bf0866fbfcf9be7741c954bc811296f750103873a6e73fa9bd274')


if __name__ == '__main__':
    unittest.main()