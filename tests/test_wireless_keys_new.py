#!/usr/bin/env python3
"""
python3 -m unittest tests/test_wireless_keys.py
"""

import unittest
from src.wireless_keys_new import *


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




if __name__ == '__main__':
    unittest.main()