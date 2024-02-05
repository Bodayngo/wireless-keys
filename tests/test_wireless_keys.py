#!/usr/bin/env python3
"""
python3 -m unittest tests/test_wireless_keys.py
"""

import unittest
from src.wireless_keys import *


class TestWirelessKeysFunctions(unittest.TestCase):

    def test_pmkid_sha1(self):
        pmk = bytes.fromhex('03304a03fb68e904d47b78429d661f8bc7f373f5de6df640e9b0f3e142a6fe5d')
        spa = bytes.fromhex('8045dd31c4c8')
        aa = bytes.fromhex('aa468d005020')
        pmkid = pmkid_sha1(pmk, aa, spa)
        self.assertIsInstance(pmkid, bytes)
        self.assertEqual(len(pmkid), 16)
        self.assertEqual(pmkid.hex(), '0db738755972d6a09cfadc3e235c9e29')

    def test_pmkid_sha256(self):
        pmk = bytes.fromhex('03304a03fb68e904d47b78429d661f8bc7f373f5de6df640e9b0f3e142a6fe5d')
        spa = bytes.fromhex('8045dd31c4c8')
        aa = bytes.fromhex('aa468d005020')
        pmkid = pmkid_sha256(pmk, aa, spa)
        self.assertIsInstance(pmkid, bytes)
        self.assertEqual(len(pmkid), 16)
        self.assertEqual(pmkid.hex(), '61eac9970bd64e1ca7820bfe9355b61b')

    def test_pmkid_sha384(self):
        pmk = bytes.fromhex('03304a03fb68e904d47b78429d661f8bc7f373f5de6df640e9b0f3e142a6fe5d')
        spa = bytes.fromhex('8045dd31c4c8')
        aa = bytes.fromhex('aa468d005020')
        pmkid  = pmkid_sha384(pmk, aa, spa)
        self.assertIsInstance(pmkid, bytes)
        self.assertEqual(len(pmkid), 16)
        self.assertEqual(pmkid.hex(), '5c819340218a382d62959ae0d2ecb554')

    def test_getAB(self):
        anonce = bytes.fromhex('13474349c681499192f7f6581121b8e60c166925fac52cc29e5d03d5a1e4acf3')
        snonce = bytes.fromhex('5d13d1569b435213f9724003655882a4d6d713a894ecd00db13ce46d8f11e960')
        spa = bytes.fromhex('2429348bb466')
        aa = bytes.fromhex('c29c2ee79b80')
        A, B = getAB(anonce, snonce, aa, spa)
        self.assertEqual(len(A), 22)
        self.assertIsInstance(A, bytes)
        self.assertEqual(A.hex(), '5061697277697365206b657920657870616e73696f6e')
        self.assertEqual(len(B), 76)
        self.assertIsInstance(B, bytes)
        self.assertEqual(B.hex(), '2429348bb466c29c2ee79b8013474349c681499192f7f6581121b8e60c166925fac52cc29e5d03d5a1e4acf35d13d1569b435213f9724003655882a4d6d713a894ecd00db13ce46d8f11e960')

    def test_prf_sha1(self):
        pmk = bytes.fromhex('8b470d911a0428b393a8396d3e0faa69d994d87f682d293c460f8262a5cbbcb1')
        A = bytes.fromhex('5061697277697365206b657920657870616e73696f6e')
        B = bytes.fromhex('2429348bb466c29c2ee79b8013474349c681499192f7f6581121b8e60c166925fac52cc29e5d03d5a1e4acf35d13d1569b435213f9724003655882a4d6d713a894ecd00db13ce46d8f11e960')
        ptk = prf_sha1(pmk, A, B, 48)
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
        pmk = bytes.fromhex('bf9721e26479f2a412dee0e89a4fef1894c3feceab36d53c6583ce96e3c7b2e5')
        A = bytes.fromhex('5061697277697365206b657920657870616e73696f6e')
        B = bytes.fromhex('8045dd31c4c8c29c2ee79b8027d0029a0464fdac4c1870740d138c504be995a4e384a5a826ee539a2df5fe7f5417cde51869ebc00200d6ac2e43ea4d774de9aadceb438383beaf696f1601e3')
        ptk = kdf_sha256(pmk, A, B, 48)
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
        pmk = bytes.fromhex('8bf26829f546c3bb66890da1fc7b0f7e3863f70a41abccd50c735fbc090863fa61639bbb3dd616c3172d068cc0188edd')
        A = bytes.fromhex('5061697277697365206b657920657870616e73696f6e')
        B = bytes.fromhex('8045dd31c4c8c29c2ee79b801ec0830d02bc8a70044ea182a12b88605fcc58495b233092fa8ba119fb94c3885c4d0eb6835565c3dc7ee4f8f36193282041a27faf9dc8dbbbc7f16eee627cd0')
        ptk = kdf_sha384(pmk, A, B, 88)
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