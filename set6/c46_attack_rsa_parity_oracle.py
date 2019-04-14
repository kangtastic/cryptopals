#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# RSA parity oracle
#
# When does this ever happen?
#
#   This is a bit of a toy problem, but it's very helpful for understanding
#   what RSA is doing (and also for why pure number-theoretic encryption is
#   terrifying). Trust us, you want to do this before trying the next
#   challenge. Also, it's fun.
#
# Generate a 1024 bit RSA key pair.
#
# Write an oracle function that uses the private key to answer the question
# "is the plaintext of this message even or odd" (is the last bit of the
# message 0 or 1). Imagine for instance a server that accepted RSA-encrypted
# messages and checked the parity of their decryption to validate them, and
# spat out an error if they were of the wrong parity.
#
# Anyways: function returning true or false based on whether the decrypted
# plaintext was even or odd, and nothing else.
#
# Take the following string and un-Base64 it in your code (without looking at
# it!) and encrypt it to the public key, creating a ciphertext:
#
#   VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IG
#   Fyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==
#
# With your oracle function, you can trivially decrypt the message.
#
# Here's why:
#
#   - RSA ciphertexts are just numbers. You can do trivial math on them. You
#     can for instance multiply a ciphertext by the RSA-encryption of another
#     number; the corresponding plaintext will be the product of those two
#     numbers.
#   - If you double a ciphertext (multiply it by (2**e)%n), the resulting
#     plaintext will (obviously) be either even or odd.
#   - If the plaintext after doubling is even, doubling the plaintext *didn't
#     wrap the modulus* --- the modulus is a prime number. That means the
#     plaintext is less than half the modulus.
#
# You can repeatedly apply this heuristic, once per bit of the message,
# checking your oracle function each time.
#
# Your decryption function starts with bounds for the plaintext of [0,n].
#
# Each iteration of the decryption cuts the bounds in half; either the upper
# bound is reduced by half, or the lower bound is.
#
# After log2(n) iterations, you have the decryption of the message.
#
# Print the upper bound of the message as a string at each iteration; you'll
# see the message decrypt "hollywood style".
#
# Decrypt the string (after encrypting it to a hidden private key) above.
#
import base64
import sys

sys.path.append("..")

from util.misc import modexp
from util.rsa import make_rsa_keys, rsa
from util.text import to_bytes, to_str

PTEXT_B64 = b"VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="


def make_oracle(privkey):
    def oracle(ctext):
        return not rsa(ctext, privkey, as_bytes=False) & 1

    return oracle


def decryptor(ctext, pubkey, oracle, show=True):
    e, n = pubkey
    two = modexp(2, e, n)

    # Decryption algorithm as described in the challenge.
    # Mostly works, but usually fails for the last character.
    #
    # lower, upper, ptext = 0, n, b""
    # while lower < upper:
    #     mid = (upper + lower) // 2
    #     if oracle(ctext):
    #         upper -= mid
    #     else:
    #         lower += mid
    # return to_bytes(upper)

    lower, upper, bit_length = 0, 1, n.bit_length()

    for i in range(1, bit_length + 1):
        diff, lower, upper = upper - lower, lower << 1, upper << 1
        ctext = (ctext * two) % n
        if oracle(ctext):
            upper -= diff
        else:
            lower += diff
        print("\r" + to_str((upper * n) >> i) + "\033[K", end="", flush=True)
    else:
        print()

    return to_bytes((upper * n) >> bit_length)


def main():
    print("Generating an RSA key pair, please wait.")

    pubkey, privkey = make_rsa_keys(bits=1024)
    oracle = make_oracle(privkey)

    print("Generating and decrypting ciphertext.")
    print()

    ctext = rsa(base64.b64decode(PTEXT_B64), pubkey, as_bytes=False)

    decryptor(ctext, pubkey, oracle)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


# Output:
#
#   Generating an RSA key pair, please wait.
#   Generating and decrypting ciphertext.
#
#   That's why I found you don't play around with the Funky Cold Medina
#
