#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright © 2019 James Seo <james@equiv.tech> (github.com/kangtastic).
# This file is released under the WTFPL, version 2 (wtfpl.net).
#
# sha1.py: An implementation of the SHA-1 hash algorithm in pure Python 3.
#
# Description: Zounds! Yet another rendition of pseudocode from Wikipedia!
#
# Usage: Why would anybody use this? This is self-rolled crypto, and
#        self-rolled *obsolete* crypto at that. DO NOT USE if you need
#        something "performant" or "secure". :P
#
#        Anyway, from the command line:
#
#           $ ./sha1.py [messages]
#
#        where [messages] are some strings to be hashed.
#
#        In Python, use similarly to hashlib:
#
#           from .sha1 import SHA1
#
#           digest = SHA1("BEES").hexdigest()
#
#           print(digest)  # "55d66cff31bed2f9ed40644a5d2d137745f5a83a"
#
#
# Sample console output:
#
#   Testing the SHA1 class.
#
#   Message:  b''
#   Expected: da39a3ee5e6b4b0d3255bfef95601890afd80709
#   Actual:   da39a3ee5e6b4b0d3255bfef95601890afd80709
#
#   Message:  b'The quick brown fox jumps over the lazy dog'
#   Expected: 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12
#   Actual:   2fd4e1c67a2d28fced849ee1bb76e7391b93eb12
#
#   Message:  b'BEES'
#   Expected: 55d66cff31bed2f9ed40644a5d2d137745f5a83a
#   Actual:   55d66cff31bed2f9ed40644a5d2d137745f5a83a
#
import struct
from functools import reduce


class SHA1:
    """An implementation of the SHA-1 hash algorithm."""

    width = 32
    mask = 0xFFFFFFFF

    digest_size = 20
    block_size = 64

    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]

    def __init__(self, msg=None):
        """:param ByteString msg: The message to be hashed."""
        if msg is None:
            msg = b""
        if isinstance(msg, str):
            msg = msg.encode()

        self.msg = msg

        # Pre-processing: Total length is a multiple of 512 bits.
        ml = len(msg) * 8
        msg += b"\x80"
        msg += b"\x00" * (-(len(msg) + 8) % 64)
        msg += struct.pack(">Q", ml)

        # Process the message in successive 512-bit chunks.
        self._process(msg[i : i + 64] for i in range(0, len(msg), 64))

    def __repr__(self):
        if self.msg:
            return f"{self.__class__.__name__}({self.msg:s})"
        return f"{self.__class__.__name__}()"

    def __str__(self):
        return self.hexdigest()

    def __eq__(self, other):
        return self.h == other.h

    def int(self):
        """:return: The final hash value as an `int`."""
        return reduce(lambda x, y: (x << SHA1.width) | y, self.h)

    def digest(self):
        """:return: The final hash value as a `bytes` object."""
        return struct.pack(">5L", *self.h)

    def hexbytes(self):
        """:return: The final hash value as hexbytes."""
        return self.hexdigest().encode()

    def hexdigest(self):
        """:return: The final hash value as a hexstring."""
        return "".join(f"{value:08x}" for value in self.h)

    def _process(self, chunks):
        for chunk in chunks:
            w = list(struct.unpack(">16L", chunk))

            # Extend the sixteen 32-bit words into eighty 32-bit words.
            for i in range(16, 80):
                value = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]
                w.append(SHA1.lrot(value, 1))

            # Initialize hash value for this chunk.
            a, b, c, d, e = self.h

            # Main loop.
            for i in range(len(w)):
                if i < 20:
                    f, k = d ^ (b & (c ^ d)), 0x5A827999
                elif i < 40:
                    f, k = b ^ c ^ d, 0x6ED9EBA1
                elif i < 60:
                    f, k = (b & c) | (d & (b | c)), 0x8F1BBCDC
                else:
                    f, k = b ^ c ^ d, 0xCA62C1D6

                temp = (SHA1.lrot(a, 5) + f + e + k + w[i]) & SHA1.mask
                e, d, c, b, a = d, c, SHA1.lrot(b, 30), a, temp

            # Add this chunk's hash to result so far.
            c_hash = [a, b, c, d, e]
            self.h = [((v + n) & SHA1.mask) for v, n in zip(self.h, c_hash)]

    @staticmethod
    def lrot(value, n):
        lbits, rbits = (value << n) & SHA1.mask, value >> (SHA1.width - n)
        return lbits | rbits


def main():
    # Import is intentionally delayed.
    import sys

    if len(sys.argv) > 1:
        messages = [msg.encode() for msg in sys.argv[1:]]
        for message in messages:
            print(SHA1(message).hexdigest())
    else:
        import hashlib

        messages = [b"", b"The quick brown fox jumps over the lazy dog", b"BEES"]

        print("Testing the SHA1 class.")
        print()

        for message in messages:
            print("Message: ", message)
            print("Expected:", hashlib.sha1(message).hexdigest())
            print("Actual:  ", SHA1(message).hexdigest())
            print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
