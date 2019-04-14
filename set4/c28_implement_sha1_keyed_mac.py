#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Implement a SHA-1 keyed MAC
#
# Find a SHA-1 implementation in the language you code in.
#
# Don't cheat. It won't work.
#
#   Do not use the SHA-1 implementation your language already provides (for
#   instance, don't use the "Digest" library in Ruby, or call OpenSSL; in
#   Ruby, you'd want a pure-Ruby SHA-1).
#
# Write a function to authenticate a message under a secret key by using a
# secret-prefix MAC, which is simply:
#
#   SHA1(key || message)
#
# Verify that you cannot tamper with the message without breaking the MAC
# you've produced, and that you can't produce a new MAC without knowing the
# secret key.
#
import sys
from hashlib import sha1

sys.path.append("..")

from util.sha1 import SHA1


def make_sha1_pmac(msg, key):
    return SHA1(key + msg)


def check_sha1_pmac(msg, key, pmac):
    return SHA1(key + msg) == pmac


def main():
    messages = [b"", b"The quick brown fox jumps over the lazy dog", b"BEES"]

    print("Testing the SHA1 class.")
    print()

    for message in messages:
        print("Message: ", message)
        print("Expected:", sha1(message).hexdigest())
        print("Actual:  ", SHA1(message).hexdigest())
        print()
    print()

    print("Generating a secret-prefix MAC.")
    message = b"The quick brown fox jumps over the lazy cog"
    key = b"An arbitrary key"
    pmac = make_sha1_pmac(message, key)
    print()

    print("Message:      ", message)
    print("Key:          ", key)
    print("MAC:          ", pmac)
    print("Authenticates:", check_sha1_pmac(message, key, pmac))
    print()

    print("MAC still authenticates after modifying message?")
    message2 = bytes(reversed(message))
    print()

    print("Message:      ", message2)
    print("Key:          ", key)
    print("MAC:          ", pmac)
    print("Authenticates:", check_sha1_pmac(message2, key, pmac))

    # OK, we get the idea.


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


# Output:
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
#
#   Generating a secret-prefix MAC.
#   Message:       b'The quick brown fox jumps over the lazy cog'
#   Key:           b'An arbitrary key'
#   MAC:           01e96bbf19a63d3b1af6fa7dbf851e077492f872
#   Authenticates: True
#
#   MAC still authenticates after modifying message?
#   Message:       b'goc yzal eht revo spmuj xof nworb kciuq ehT'
#   Key:           b'An arbitrary key'
#   MAC:           01e96bbf19a63d3b1af6fa7dbf851e077492f872
#   Authenticates: False
#
