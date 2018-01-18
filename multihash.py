"""Multihash implementation in Python."""

import warnings
import hashlib
import struct
import io

import six

# These are the subset of https://raw.githubusercontent.com/multiformats/multihash/master/hashtable.csv
# which are supported by hashlib or external libraries

# TODO: perhaps we should just make this periodically rebuilt from hashtable.csv?
CODECS = [
    ('md5', 0xd5, hashlib.md5),
    ('sha1', 0x11, hashlib.sha1),
    ('sha2-256', 0x12, hashlib.sha256),
    ('sha2-512', 0x13, hashlib.sha512),
]

try:
    # Python 3.6 has SHA-3 support built-in; the sha3 backport will add those values to hashlib:
    if not hasattr(hashlib, 'sha3_512'):
        import sha3  # NOQA

    CODECS.extend((
        ('sha3-224', 0x17, hashlib.sha3_224),
        ('sha3-256', 0x16, hashlib.sha3_256),
        ('sha3-384', 0x15, hashlib.sha3_384),
        ('sha3-512', 0x14, hashlib.sha3_512),
    ))
except ImportError:
    warnings.warn('multihash requires the sha3 library to be installed on Python <3.6')


try:
    if not hasattr(hashlib, 'blake2b'):
        import pyblake2
        hashlib.blake2b = pyblake2.blake2b
        hashlib.blake2s = pyblake2.blake2s

    CODECS.extend((
        ('blake2b-64', 0xb208, hashlib.blake2b),
        ('blake2s-32', 0xb244, hashlib.blake2s),
    ))
except ImportError:
    warnings.warn('multihash requires the sha3 library to be installed on Python <3.6')

# Since these are accessed frequently we'll have some convenience lookup dictionaries:
CODECS_BY_NAME = {name: function for name, code, function in CODECS}
CODECS_BY_CODE = {code: function for name, code, function in CODECS}
CODES_BY_NAME = {name: code for name, code, function in CODECS}

DIGEST_BYTE_LENGTHS = {
    'md5':          16,
    'sha1':         20,
    'sha2-256':     32,
    'sha2-512':     64,
    'sha3-512':     64,
    'blake2b':      64,
    'blake2s':      32,
}


def get_hash_function(hash_identifier):
    """Return an initialised hash object, by function, name or integer id"""

    if six.callable(hash_identifier):
        return hash_identifier()
    elif isinstance(hash_identifier, six.integer_types):
        return CODECS_BY_CODE[hash_identifier]
    elif isinstance(hash_identifier, six.string_types):
        if hash_identifier == 'sha3':
            warnings.warn('The codec name "sha3" should be "sha3-512"', category=DeprecationWarning)
            return CODECS_BY_NAME['sha3-512']

        if hash_identifier in CODECS_BY_NAME:
            return CODECS_BY_NAME[hash_identifier]
        elif hash_identifier.isdigit():
            return CODECS_BY_CODE[int(hash_identifier)]

    raise ValueError('Unknown hash function "{0}"'.format(hash_identifier))


def is_app_code(code):
    """Check if the code is an application specific code.

    >>> is_app_code(SHA1)
    False
    >>> is_app_code(0)
    True
    """

    if isinstance(code, six.integer_types):
        return code >= 0 and code < 0x10
    else:
        return False


def is_valid_code(code):
    """Check if the digest algorithm code is valid"""

    warnings.warn('is_valid_code() is deprecated; use get_code() instead', DeprecationWarning)

    if get_code(code):
        return True
    else:
        return False


def get_code(identifier):
    if identifier in CODECS_BY_CODE:
        return identifier
    elif identifier in CODES_BY_NAME:
        return CODES_BY_NAME[identifier]
    elif is_app_code(identifier):
        return identifier
    else:
        raise ValueError('%s is not a recognized codec identifier' % identifier)


def decode(buf):
    r"""Decode a hash from the given Multihash.

    After validating the hash type and length in the two prefix bytes, this
    function removes them and returns the codec ID and the raw hash. For
    supported hash functions the codec ID can be used with `get_hash_function()`.
    """

    if len(buf) < 3:
        raise ValueError('Buffer too short')

    if len(buf) > 129:
        raise ValueError('Buffer too long')

    code, length = struct.unpack('BB', buf[:2])

    # This is stricter than get_code since it should only check the numeric code values:
    if code not in CODECS_BY_CODE:
        raise ValueError('Invalid code "{0}"'.format(code))

    digest = buf[2:]
    if len(digest) != length:
        raise ValueError('Inconsistent length ({0} != {1})'.format(len(digest), length))

    return code, digest


def encode(content, codec_identifier):
    """
    Return the multihash-format digest for the provided content and codec type

    :param content:
        The payload as bytes, text (which will be calculated assuming UTF-8 encoding),
        a file-like object compatible with io.BufferedReader, or an iterable which
        yields bytes.

    :param codec_identifier:
        The name or multihash code ID for the codec to use
    """

    code = get_code(codec_identifier)

    hash_function = get_hash_function(code)

    hasher = hash_function()

    if isinstance(content, six.binary_type):
        hasher.update(content)
    elif isinstance(content, six.string_types):
        hasher.update(content.encode('utf-8'))
    elif isinstance(content, io.BufferedReader):
        while True:
            chunk = content.read(1048576)
            if len(chunk) == 0:
                break
            hasher.update(chunk)
    elif hasattr(content, '__iter__'):
        for chunk in content:
            hasher.update(chunk)
    else:
        raise TypeError('%r is not a supported input type. Provide bytes, unicode,'
                        ' an io.BufferedReader file-like object, or an iteratable yielding bytes')

    digest = hasher.digest()

    return encode_multihash(digest, code)


def encode_multihash(digest, code):
    """
    Given a precalculated digest, return the multihash packed code + digest value
    """

    if len(digest) > 127:
        raise ValueError('multihash does not support digest length > 127')

    output = bytearray([code, len(digest)])
    output.extend(digest)

    return output
