import codecs
import hashlib
import io
import sys
import warnings
from unittest import TestCase

import multihash


class CoreAPITests(TestCase):
    def test_get_hash_algorithm(self):
        self.assertEqual(hashlib.sha1, multihash.get_hash_function('sha1'))
        self.assertEqual(hashlib.sha1, multihash.get_hash_function(0x11))
        self.assertEqual(hashlib.md5, multihash.get_hash_function('md5'))
        self.assertEqual(hashlib.md5, multihash.get_hash_function(0xd5))

        self.assertRaises(ValueError, multihash.get_hash_function, 'sha-nonexistent')

    def test_get_hash_algorithm_deprecated(self):
        with warnings.catch_warnings(record=True) as w:
            # Cause all warnings to always be triggered.
            warnings.simplefilter("always")

            self.assertEqual(hashlib.sha3_512, multihash.get_hash_function('sha3'))

            self.assertEqual(len(w), 1)
            self.assertTrue(issubclass(w[-1].category, DeprecationWarning))

    def test_encode_unicode(self):
        encoded = multihash.encode('testing', 'sha1')
        self.assertEqual(22, len(encoded))
        self.assertEqual(encoded[0], multihash.CODES_BY_NAME['sha1'])
        self.assertEqual(encoded[1], 0x14)
        self.assertEqual(encoded[2:], b'\xdcrJ\xf1\x8f\xbd\xd4\xe5\x91\x89\xf5\xfev\x8a_\x83\x11RpP')

    def test_encode_bytes(self):
        encoded = multihash.encode('testbytes', 'sha1')
        self.assertEqual(22, len(encoded))
        self.assertEqual(encoded[0], multihash.CODES_BY_NAME['sha1'])
        self.assertEqual(encoded[1], 0x14)
        self.assertEqual(encoded[2:], b't-\x96\x02\x00K"j\xb5!!\xe4\xe4)\xf3\x7f\xd0.\xf7m')

    def test_encode_bufferedreader(self):
        bytes_io = io.BytesIO(b'TEST BYTES')
        encoded = multihash.encode(bytes_io, 'sha1')
        self.assertEqual(22, len(encoded))
        self.assertEqual(encoded[0], multihash.CODES_BY_NAME['sha1'])
        self.assertEqual(encoded[1], 0x14)
        self.assertEqual(encoded[2:], b'G\x85\x18\xd0)\x1f*\xecsI\xc1\xe9_j\xb0OW\xb5\x10\xc9')

    def test_decode(self):
        encoded = b'\x11\x14\xc3\xd4XGWbx`AAh\x01%\xa4o\xef9Nl('
        codec_id, decoded = multihash.decode(encoded)
        self.assertEqual(multihash.CODES_BY_NAME['sha1'], codec_id)
        self.assertEqual(decoded, bytearray(b'\xc3\xd4XGWbx`AAh\x01%\xa4o\xef9Nl('))


class SpecCompatibilityTests(TestCase):

    def test_hardcoded_examples(self):
        # Source: https://github.com/multiformats/multihash#example

        encoded = multihash.encode("multihash", "sha1")
        self.assertEqual(encoded, codecs.decode('111488c2f11fb2ce392acb5b2986e640211c4690073e', 'hex_codec'))

        encoded = multihash.encode("multihash", "sha2-256")
        self.assertEqual(
            encoded,
            codecs.decode('12209cbc07c3f991725836a3aa2a581ca2029198aa420b9d99bc0e131d9f3e2cbe47', 'hex_codec')
        )
