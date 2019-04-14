# -*- coding: utf-8 -*-
from hashlib import sha256

from .sha1 import SHA1


def hmac(key, message, hash_class):
    block_size = hash_class().block_size

    if len(key) > block_size:
        key = hash_class(key).digest()
    key = key.ljust(block_size, b"\x00")

    mac = message.encode() if isinstance(message, str) else message
    for pad_byte in b"\x5c", b"\x36":
        prefix = bytes(kb ^ pb for kb, pb in zip(key, pad_byte * block_size))
        mac = hash_class(prefix + mac).digest()

    return mac


def hmac_sha1(key, message):
    return hmac(key, message, SHA1)


def hmac_sha256(key, message):
    return hmac(key, message, sha256)
