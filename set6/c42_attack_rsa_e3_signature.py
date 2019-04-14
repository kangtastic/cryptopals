#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Bleichenbacher's e=3 RSA Attack
#
# Crypto-tourism informational placard.
#
#   This attack broke Firefox's TLS certificate validation several years ago.
#   You could write a Python script to fake an RSA signature for any
#   certificate. We find new instances of it every other year or so.
#
# RSA with an encrypting exponent of 3 is popular, because it makes the RSA
# math faster.
#
# With e=3 RSA, encryption is just cubing a number mod the public encryption
# modulus:
#
#   c = m ** 3 % n
#
# e=3 is secure as long as we can make assumptions about the message blocks
# we're encrypting. The worry with low-exponent RSA is that the message blocks
# we process won't be large enough to wrap the modulus after being cubed. The
# block 00:02 (imagine sufficient zero-padding) can be "encrypted" in e=3 RSA;
# it is simply 00:08.
#
# When RSA is used to sign, rather than encrypt, the operations are reversed;
# the verifier "decrypts" the message by cubing it. This produces a
# "plaintext" which the verifier checks for validity.
#
# When you use RSA to sign a message, you supply it a block input that
# contains a message digest. The PKCS1.5 standard formats that block as:
#
#   00h 01h ffh ffh ... ffh ffh 00h ASN.1 GOOP HASH
#
# As intended, the ffh bytes in that block expand to fill the whole block,
# producing a "right-justified" hash (the last byte of the hash is the last
# byte of the message).
#
# There was, 7 years ago, a common implementation flaw with RSA verifiers:
# they'd verify signatures by "decrypting" them (cubing them modulo the public
# exponent) and then "parsing" them by looking for:
#
#   00h 01h ... ffh 00h ASN.1 HASH
#
# This is a bug because it implies the verifier isn't checking all the
# padding. If you don't check the padding, you leave open the possibility that
# instead of hundreds of ffh bytes, you have only a few, which if you think
# about it means there could be squizzilions of possible numbers that could
# produce a valid-looking signature.
#
# How to find such a block? Find a number that when cubed:
#   a) doesn't wrap the modulus (thus bypassing the key entirely) and
#   b) produces a block that starts "00h 01h ffh ... 00h ASN.1 HASH".
#
# There are two ways to approach this problem:
#
#   - You can work from Hal Finney's writeup, available on Google, of how
#     Bleichenbacher explained the math "so that you can do it by hand with a
#     pencil".
#   - You can implement an integer cube root in your language, format the
#     message block you want to forge, leaving sufficient trailing zeros at
#     the end to fill with garbage, then take the cube-root of that block.
#
# Forge a 1024-bit RSA signature for the string "hi mom". Make sure your
# implementation actually accepts the signature!
#
import inspect
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(inspect.getfile(lambda: 0)))))

from util.misc import nth_root
from util.rsa import make_rsa_keys, rsa
from util.sha1 import SHA1
from util.text import byte_length, from_bytes, to_bytes

ASN_1 = bytes.fromhex("003021300906052B0E03021A05000414")


def sign_rsa(bs, privkey, hash_cls=SHA1):
    # The hash subjected to the RSA "decryption" is padded to
    # the same length as the RSA modulus according to PKCS#1.5.
    phash = ASN_1 + hash_cls(bs).digest()
    phash = b"\x00\x01" + phash.rjust(byte_length(privkey[1]) - 2, b"\xff")
    return rsa(phash, privkey)


def verify_rsa(bs, sig, pubkey, hash_cls=SHA1):
    phash = rsa(sig, pubkey)

    # Knock off leading 0x01, at least one 0xff, and ASN.1 magic.
    # NOTE: rsa() already knocks off leading 0x00.
    if phash.startswith(b"\x01\xff"):
        phash = phash[1:]
        while phash[0] == 0xFF:
            phash = phash[1:]
        if phash.startswith(ASN_1):
            phash = phash[len(ASN_1) :]

    return phash.startswith(hash_cls(bs).digest())


def forge_rsa_e3(bs, pubkey, hash_cls=SHA1):
    e, n = pubkey
    n_byte_length = byte_length(n)

    # Craft a padded hash that begins with "0x0001ff00<ASN.1><ptext_digest>",
    # ends with pretty much anything, and is as long as the modulus.
    phash = b"\x00\x01\xff" + ASN_1 + hash_cls(bs).digest()
    phash = phash.ljust(n_byte_length, b"\xff")

    # Find the integer e'th root of this hash; it doesn't need to be perfect.
    eth_root = nth_root(from_bytes(phash), e)
    forged_sig = to_bytes(eth_root)

    # Final forged signature is right-justified to be as long as the modulus.
    return forged_sig.rjust(n_byte_length, b"\x00")


def _test_rsa_signing(ptext, bits=1024, hash_cls=SHA1):
    print("Generating a public/private key pair, please wait.")
    pubkey, privkey = make_rsa_keys(bits)

    print(f"Signing '{ptext.decode()}'.")
    sig = sign_rsa(ptext, privkey, hash_cls)

    print("Signature validates:", verify_rsa(ptext, sig, pubkey, hash_cls))


def _test_rsa_forging(ptext, bits=1024, hash_cls=SHA1):
    print("Generating a public key, please wait.")
    pubkey = make_rsa_keys(bits)[0]  # Discard the private key.

    print(f"Forging a signature for '{ptext.decode()}'.")
    sig = forge_rsa_e3(ptext, pubkey, hash_cls)

    print("Forgery validates:", verify_rsa(ptext, sig, pubkey, hash_cls))


def main():
    # Intentionally delayed import.
    from hashlib import sha256

    tests = {
        "Testing our RSA signature implementation.": [
            _test_rsa_signing,
            b"Mary had a little lamb",
            b"His fleece was white as snow",
        ],
        "Now, we'll forge signatures that can fool it.": [
            _test_rsa_forging,
            b"hi mom",
            b"And everywhere that Mary went",
        ],
    }

    for description, test in tests.items():
        print(description)
        print()

        func = test[0]

        print("Using 1024-bit modulus, SHA-1 hash.")
        func(test[1], 1024, SHA1)
        print()

        print("Using 1536-bit modulus, SHA-256 hash.")
        func(test[2], 1536, sha256)
        print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


# Output:
#
#   Testing our RSA signature implementation.
#
#   Using 1024-bit modulus, SHA-1 hash.
#   Generating a public/private key pair, please wait.
#   Signing 'Mary had a little lamb'.
#   Signature validates: True
#
#   Using 1536-bit modulus, SHA-256 hash.
#   Generating a public/private key pair, please wait.
#   Signing 'His fleece was white as snow'.
#   Signature validates: True
#
#   Now, we'll forge signatures that can fool it.
#
#   Using 1024-bit modulus, SHA-1 hash.
#   Generating a public key, please wait.
#   Forging a signature for 'hi mom'.
#   Forgery validates: True
#
#   Using 1536-bit modulus, SHA-256 hash.
#   Generating a public key, please wait.
#   Forging a signature for 'And everywhere that Mary went'.
#   Forgery validates: True
#
