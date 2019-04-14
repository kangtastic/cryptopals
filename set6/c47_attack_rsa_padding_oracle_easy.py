#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)
#
# Degree of difficulty: moderate
#
#   These next two challenges are the hardest in the entire set.
#
# Let us Google this for you: "Chosen ciphertext attacks against protocols
# based on the RSA encryption standard"
#
# This is Bleichenbacher from CRYPTO '98; I get a bunch of .ps versions on
# the first search page.
#
# Read the paper. It describes a padding oracle attack on PKCS#1v1.5. The
# attack is similar in spirit to the CBC padding oracle you built earlier;
# it's an "adaptive chosen ciphertext attack", which means you start with a
# valid ciphertext and repeatedly corrupt it, bouncing the adulterated
# ciphertexts off the target to learn things about the original.
#
# This is a common flaw even in modern cryptosystems that use RSA.
#
# It's also the most fun you can have building a crypto attack. It involves
# 9th grade math, but also has you implementing an algorithm that is complex
# on par with finding a minimum cost spanning tree.
#
# The setup:
#
#   - Build an oracle function, just like you did in the last exercise, but
#     have it check for plaintext[0] == 0 and plaintext[1] == 2.
#   - Generate a 256 bit keypair (that is, p and q will each be 128 bit
#     primes), [n, e, d].
#   - Plug d and n into your oracle function.
#   - PKCS1.5-pad a short message, like "kick it, CC", and call it "m".
#     Encrypt to to get "c".
#   - Decrypt "c" using your padding oracle.
#
# For this challenge, we've used an untenably small RSA modulus (you could
# factor this keypair instantly). That's because this exercise targets a
# specific step in the Bleichenbacher paper --- Step 2c, which implements a
# fast, nearly O(log n) search for the plaintext.
#
# Things you want to keep in mind as you read the paper:
#
#   - RSA ciphertexts are just numbers.
#   - RSA is "homomorphic" with respect to multiplication, which means you can
#     multiply c * RSA(2) to get a c' that will decrypt to plaintext * 2. This
#     is mindbending but easy to see if you play with it in code --- try
#     multiplying ciphertexts with the RSA encryptions of numbers so you know
#     you grok it.
#   - What you need to grok for this challenge is that Bleichenbacher uses
#     multiplication on ciphertexts the way the CBC oracle uses XORs of random
#     blocks.
#   - A PKCS#1v1.5 conformant plaintext, one that starts with 00:02, must be a
#     number between 02:00:00...00 and 02:FF:FF..FF --- in other words, 2B and
#     3B-1, where B is the bit size of the modulus minus the first 16 bits.
#     When you see 2B and 3B, that's the idea the paper is playing with.
#
# To decrypt "c", you'll need Step 2a from the paper (the search for the first
# "s" that, when encrypted and multiplied with the ciphertext, produces a
# conformant plaintext), Step 2c, the fast O(log n) search, and Step 3.
#
# Your Step 3 code is probably not going to need to handle multiple ranges.
#
# We recommend you just use the raw math from paper (check, check, double
# check your translation to code) and not spend too much time trying to grok
# how the math works.
import sys

sys.path.append("..")

from util.misc import invmod, modexp
from util.rsa import make_rsa_keys, rsa
from util.text import byte_length, pad_pkcs15, unpad_pkcs15


def make_oracle(privkey):
    bsize = byte_length(privkey[1])

    def oracle(ctext):
        ptext = rsa(ctext, privkey)
        return ptext.rjust(bsize, b"\x00")[:2] == b"\x00\x02"

    return oracle


def decrypt_prepare(ctext, pubkey, oracle):
    # Extract/precompute some numbers that show up often in the math.
    e, n = pubkey
    B = 1 << 8 * (byte_length(n) - 2)
    B_2, B_3, B_31 = 2 * B, 3 * B, 3 * B - 1
    M_0 = {(B_2, B_31)}

    for s_0 in range(1, n + 1):
        c_0 = (ctext * modexp(s_0, e, n)) % n
        if oracle(c_0):
            constants = (e, n, c_0, s_0, B, B_2, B_3, B_31)
            state = (1, s_0, M_0)
            return constants, state


def decrypt_pass(constants, state, oracle):
    e, n, c_0, s_0, B, B_2, B_3, B_31 = constants
    i, s_i1, M_i1 = state

    # Find s_i.
    if i == 1 or (i > 1 and len(M_i1) > 1):
        s_i = (n + B_31) // B_3 if i == 1 else s_i1 + 1
        while not oracle((c_0 * modexp(s_i, e, n)) % n):
            s_i += 1
    else:
        a, b = list(M_i1)[0]
        r_i = ((2 * (b * s_i1 - B_2)) + (n - 1)) // n
        while True:
            lower = (B_2 + (r_i * n) + (b - 1)) // b
            upper = (B_3 + (r_i * n) + (a - 1)) // a
            for s_i in range(lower, upper):
                if oracle((c_0 * modexp(s_i, e, n)) % n):
                    break
            else:
                r_i += 1
                continue
            break

    # Find M_i.
    M_i = set()

    for a, b in M_i1:
        lower = ((a * s_i) - B_31 + (n - 1)) // n
        upper = ((b * s_i) - B_2) // n
        for r in range(lower, upper + 1):
            a_i = (B_2 + (r * n) + (s_i - 1)) // s_i
            b_i = (B_31 + (r * n)) // s_i
            M_i.add((max(a, a_i), min(b, b_i)))

    if len(M_i) == 1:
        a, b = list(M_i)[0]
        if a == b:
            return (a * invmod(s_0, n)) % n

    state = (i + 1, s_i, M_i)
    return constants, state


def main():
    ptext = b"kick it, CC"

    print(f"Original plaintext: '{ptext.decode()}'")
    print()

    print("Generating an RSA-256 key pair.")
    pubkey, privkey = make_rsa_keys(256)
    bsize, oracle = byte_length(pubkey[1]), make_oracle(privkey)

    print("Padding and encrypting plaintext using PKCS#1 1.5.")
    padded = pad_pkcs15(ptext, bsize)
    ctext = rsa(padded, pubkey, as_bytes=False)

    print("Cracking ciphertext, please wait.")
    decrypt_state = decrypt_prepare(ctext, pubkey, oracle)
    while not isinstance(decrypt_state, int):
        decrypt_state = decrypt_pass(*decrypt_state, oracle)
    print()

    result = unpad_pkcs15(decrypt_state, bsize)
    print(f"Cracked plaintext: '{result.decode()}'")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass

# Output:
#
#   Original plaintext: 'kick it, CC'
#
#   Generating an RSA-256 key pair.
#   Padding and encrypting plaintext.
#   Cracking ciphertext, please wait.
#
#   Cracked plaintext: 'kick it, CC'
