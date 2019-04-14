#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# DSA nonce recovery from repeated nonce
#
# Cryptanalytic MVP award.
#
#   This attack (in an elliptic curve group) broke the PS3. It is a great,
#   great attack.
#
# In this file:
#
#   https://cryptopals.com/static/challenge-data/44.txt
#
# find a collection of DSA-signed messages. (NB: each msg has a trailing
# space.)
#
# These were signed under the following pubkey:
#
#   y = 2d026f4bf30195ede3a088da85e398ef869611d0f68f07
#       13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8
#       5519b1c23cc3ecdc6062650462e3063bd179c2a6581519
#       f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430
#       f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3
#       2971c3de5084cce04a2e147821
#
# (using the same domain parameters as the previous exercise)
#
# It should not be hard to find the messages for which we have accidentally
# used a repeated "k". Given a pair of such messages, you can discover the "k"
# we used with the following formula:
#
#       (m1 - m2)
#   k = --------- mod q
#       (s1 - s2)
#
# 9th Grade Math: Study It!
#
#   If you want to demystify this, work out that equation from the original
#   DSA equations.
#
# Basic cyclic group math operations want to screw you.
#
#   Remember all this math is mod q; s2 may be larger than s1, for instance,
#   which isn't a problem if you're doing the subtraction mod q. If you're
#   like me, you'll definitely lose an hour to forgetting a paren or a mod q.
#   (And don't forget that modular inverse function!)
#
# What's my private key? Its SHA-1 (from hex) is:
#
#   ca8f6f7c66fa362d40760d135b763eb8527d3d52
#
import inspect
import os
import sys
from itertools import combinations

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(inspect.getfile(lambda: 0)))))

from util.dsa import G, P, Q
from util.loader import loader
from util.misc import invmod
from util.sha1 import SHA1
from util.text import from_bytes, to_bytes, to_hexstring


def recover_dsa_privkey(k, r, s, z, p=P, q=Q, g=G):
    k_inv = invmod(k, q)
    if k_inv is None:
        return None

    x = (((((s * k) % q) - z) % q) * invmod(r, q)) % q

    # This check isn't necessary. :)
    # from util.misc import modexp
    #
    # sk, rk = (k_inv * (z + x * r)) % q, modexp(g, k, p) % q
    # if s == sk and r == rk:
    #     return x

    return x


def main():
    # NOTE BEFORE STARTING: Do not be fooled! Signatures are created using
    # private keys, notwithstanding the (perhaps intentionally misleading?)
    # wording in this and the previous challenge that might imply otherwise.

    lines = loader("44.txt", lambda l: l.rstrip("\n").split(": "))

    msgs = []

    for i in range(0, len(lines), 4):
        block = lines[i : i + 4]

        # After the rstrip() and split() above, a block looks like:
        #
        #   [["msg", "Listen for me, you better listen for me now. "],
        #    ["s", "1267396447369736888040262262183731677867615804316"],
        #    ["r", "1105520928110492191417703162650245113664610474875"],
        #    ["m", "a4db3de27e2db3e5ef085ced2bced91b82e0df19"]]
        #
        # We have a message, the components of a DSA signature, and the SHA1
        # hash of the message. Everything here's a `str` at the moment, so
        # we'll transform the values.
        #
        # There's an error in "m" for one of the blocks in the challenge data,
        # but we can just calculate the hash ourselves.
        block[0][1] = block[0][1].encode()
        block[1][1] = int(block[1][1])
        block[2][1] = int(block[2][1])
        block[3][1] = from_bytes(SHA1(block[0][1]).digest())

        msgs.append({data[0]: data[1] for data in block})

    print(f"Loaded {len(msgs)} DSA-signed messages.")
    print("Recovering private key from the first repeated nonce we detect.")

    for msg1, msg2 in combinations(msgs, 2):
        if msg1["r"] != msg2["r"]:
            continue

        m1, m2 = msg1["m"], msg2["m"]
        s1, s2 = msg1["s"], msg2["s"]

        k = (((m1 - m2) % Q) * invmod(s1 - s2, Q)) % Q

        privkey = recover_dsa_privkey(k, msg1["r"], s1, m1)
        digest = SHA1(to_hexstring(to_bytes(privkey))).hexdigest()
        assert digest == "ca8f6f7c66fa362d40760d135b763eb8527d3d52"

        print()
        print("Recovered key:", privkey)

        break
    else:
        print("Failed to recover key!")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


# Output:
#
#   Loaded 11 DSA-signed messages.
#   Recovering private key from the first repeated nonce we detect.
#
#   Recovered key: 1379952329417023174824742221952501647027600451162
#
