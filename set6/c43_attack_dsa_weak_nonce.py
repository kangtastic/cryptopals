#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# DSA key recovery from nonce
#
# Step 1: Relocate so that you are out of easy travel distance of us.
# Step 2: Implement DSA, up to signing and verifying, including parameter
#         generation.
#
# Hah-hah you're too far away to come punch us.
#
# Just kidding you can skip the parameter generation part if you want; if you
# do, use these params:
#
#   p = 800000000000000089e1855218a0e7dac38136ffafa72eda7
#       859f2171e25e65eac698c1702578b07dc2a1076da241c76c6
#       2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe
#       ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2
#       b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87
#       1a584471bb1
#
#   q = f4f47f05794b256174bba6e9b396a7707e563c5b
#
#   g = 5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119
#       458fef538b8fa4046c8db53039db620c094c9fa077ef389b5
#       322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047
#       0f5b64c36b625a097f1651fe775323556fe00b3608c887892
#       878480e99041be601a62166ca6894bdd41a7054ec89f756ba
#       9fc95302291
#
# ("But I want smaller params!" Then generate them yourself.)
#
# The DSA signing operation generates a random subkey "k". You know this
# because you implemented the DSA sign operation.
#
# This is the first and easier of two challenges regarding the DSA "k" subkey.
#
# Given a known "k", it's trivial to recover the DSA private key "x":
#
#       (s * k) - H(msg)
#   x = ----------------  mod q
#               r
#
# Do this a couple times to prove to yourself that you grok it. Capture it in
# a function of some sort.
#
# Now then. I used the parameters above. I generated a keypair. My pubkey is:
#
#   y = 84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4
#       abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004
#       e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed
#       1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b
#       bb283e6633451e535c45513b2d33c99ea17
#
# I signed:
#
#   For those that envy a MC it can be hazardous to your health
#   So be friendly, a matter of life and death, just like a etch-a-sketch
#
# (My SHA1 for this string was d2d0714f014a9784047eaeccf956520045c45265; I
# don't know what NIST wants you to do, but when I convert that hash to an
# integer I get: 0xd2d0714f014a9784047eaeccf956520045c45265).
#
# I get:
#
#   r = 548099063082341131477253921760299949438196259240
#   s = 857042759984254168557880549501802188789837994940
#
# I signed this string with a broken implemention of DSA that generated "k"
# values between 0 and 2^16. What's my private key?
#
# Its SHA-1 fingerprint (after being converted to hex) is:
#
#   0954edd5e0afe5542a4adf012611a91912a3ec16
#
# Obviously, it also generates the same signature for that string.
#
import sys

sys.path.append("..")

from util.dsa import G, P, Q, dsa_sign, dsa_verify, make_dsa_keys
from util.misc import invmod, modexp
from util.sha1 import SHA1
from util.text import from_bytes, print_indent, to_bytes, to_hexstring


def bruteforce_dsa_privkey(bs, sig, max_k=2 ** 16, p=P, q=Q, g=G):
    r, s = sig
    z = from_bytes(SHA1(bs).digest())

    for k in range(1, max_k):
        k_inv = invmod(k, q)
        if k_inv is None:
            continue

        x = (((((s * k) % q) - z) % q) * invmod(r, q)) % q

        sk, rk = (k_inv * (z + x * r)) % q, modexp(g, k, p) % q
        if s == sk and r == rk:
            return x


def _test_dsa():
    ptext = b"Hickory dickory dock"
    pubkey, privkey = make_dsa_keys()
    sig = dsa_sign(ptext, privkey)

    print(
        f"Signature validates for '{ptext.decode()}':", dsa_verify(ptext, sig, pubkey)
    )


def main():
    print("First, we'll test our DSA implementation.")
    _test_dsa()
    print()

    print("Now, let's bruteforce a DSA private key from a 16-bit subkey.")
    print()

    ptext = (
        b"For those that envy a MC it can be hazardous to your health\n"
        b"So be friendly, a matter of life and death, just like a etch-a-sketch\n"
    )
    sig = [
        548099063082341131477253921760299949438196259240,
        857042759984254168557880549501802188789837994940,
    ]

    print(f"Plaintext:")
    print_indent(*ptext.split(b"\n"), width=70, as_hex=False)

    print(f"Bruteforced private key:")
    privkey = bruteforce_dsa_privkey(ptext, sig)
    print_indent(privkey, as_hex=False)

    # This part is a little convoluted, but the SHA-1 hashes mentioned
    # in the challenge must've been mentioned ~for a reason~!!
    known_sha1s = [
        "d2d0714f014a9784047eaeccf956520045c45265",
        "0954edd5e0afe5542a4adf012611a91912a3ec16",
    ]
    sha1s = [SHA1(ptext).hexdigest(), SHA1(to_hexstring(to_bytes(privkey))).hexdigest()]
    print(
        "Calculated hashes match for plaintext and private key:",
        all(a == b for a, b in zip(known_sha1s, sha1s)),
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


# Output:
#
#   First, we'll test our DSA implementation.
#   Signature validates for 'Hickory dickory dock': True
#
#   Now, let's bruteforce a DSA private key from a 16-bit subkey.
#
#   Plaintext:
#
#       For those that envy a MC it can be hazardous to your health
#       So be friendly, a matter of life and death, just like a etch-a-sketch
#
#   Bruteforced private key:
#
#       125489817134406768603130881762531825565433175625
#
#   Calculated hashes match for plaintext and private key: True
#
