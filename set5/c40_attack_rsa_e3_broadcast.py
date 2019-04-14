#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Implement an E=3 RSA Broadcast attack
#
# Assume you're a Javascript programmer. That is, you're using a naive
# handrolled RSA to encrypt without padding.
#
# Assume you can be coerced into encrypting the same plaintext three times,
# under three different public keys. You can; it's happened.
#
# Then an attacker can trivially decrypt your message, by:
#
#   1. Capturing any 3 of the ciphertexts and their corresponding pubkeys
#   2. Using the CRT to solve for the number represented by the three
#      ciphertexts (which are residues mod their respective pubkeys)
#   3. Taking the cube root of the resulting number
#
# The CRT says you can take any number and represent it as the combination of
# a series of residues mod a series of moduli. In the three-residue case, you
# have:
#
#   result =
#       (c_0 * m_s_0 * invmod(m_s_0, n_0)) +
#       (c_1 * m_s_1 * invmod(m_s_1, n_1)) +
#       (c_2 * m_s_2 * invmod(m_s_2, n_2)) mod N_012
#
#   where:
#
#       c_0, c_1, c_2 are the three respective residues mod
#       n_0, n_1, n_2
#
#       m_s_n (for n in 0, 1, 2) are the product of the moduli
#       EXCEPT n_n --- ie, m_s_1 is n_0 * n_2
#
#       N_012 is the product of all three moduli
#
# To decrypt RSA using a simple cube root, leave off the final modulus
# operation; just take the raw accumulated result and cube-root it.
#
import inspect
import os
import random
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(inspect.getfile(lambda: 0)))))

from util.misc import invmod, nth_root
from util.rsa import make_rsa_keys, rsa
from util.text import from_bytes, print_indent, to_bytes


PTEXTS = [
    b"Humpty Dumpty sat on a wall",
    b"Humpty Dumpty had a great fall",
    b"All the king's horses and all the king's men",
    b"Couldn't put Humpty together again",
]


def main():
    ptext = random.choice(PTEXTS)

    print("Generating 3 public RSA keys and encrypting a plaintext.")
    print()

    n, c = [], []

    for i in range(3):
        pubkey, privkey = make_rsa_keys()
        ctext = rsa(ptext, pubkey)
        assert rsa(ctext, privkey) == ptext

        print(f"Ciphertext {i}:")
        print_indent(ctext)

        n.append(pubkey[1])
        c.append(from_bytes(ctext))

    if len(set(c)) == 1:
        print("The ciphertexts are sometimes identical.")
        print("This is fine; we also rely upon the public keys differing.")
        print()

    result, n_012 = 0, 1

    for i in range(3):
        ms = n[(i + 1) % 3] * n[(i + 2) % 3]
        result += c[i] * ms * invmod(ms, n[i])

        n_012 *= n[i]

    result = nth_root(result % n_012, 3)

    print("Cracked plaintext:")
    print_indent(to_bytes(result), as_hex=False)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass

# Output:
#
#   Generating 3 public keys and encrypting a plaintext.
#
#   Ciphertext 0:
#
#       04ade8854493f161013b072321595145f49aab1aec9f66ee8602d6aae6c461cd85
#       cfaa74fa54f6516809a98010961a5cf98993d7a39b91db5b17be957bb2f0ec906c
#       46296fdb512c9ffcd6b6f6169586498b22e7f769c71aa7f088109783da666b8bb9
#       72fb38
#
#   Ciphertext 1:
#
#       04ade8854493f161013b072321595145f49aab1aec9f66ee8602d6aae6c461cd85
#       cfaa74fa54f6516809a98010961a5cf98993d7a39b91db5b17be957bb2f0ec906c
#       46296fdb512c9ffcd6b6f6169586498b22e7f769c71aa7f088109783da666b8bb9
#       72fb38
#
#   Ciphertext 2:
#
#       04ade8854493f161013b072321595145f49aab1aec9f66ee8602d6aae6c461cd85
#       cfaa74fa54f6516809a98010961a5cf98993d7a39b91db5b17be957bb2f0ec906c
#       46296fdb512c9ffcd6b6f6169586498b22e7f769c71aa7f088109783da666b8bb9
#       72fb38
#
#   The ciphertexts are sometimes identical.
#   This is fine; we (also) rely upon the public keys differing.
#
#   Cracked plaintext:
#
#       Couldn't put Humpty together again
#
