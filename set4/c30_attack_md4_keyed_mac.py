#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Break an MD4 keyed MAC using length extension
#
# Second verse, same as the first, but use MD4 instead of SHA-1. Having done
# this attack once against SHA-1, the MD4 variant should take much less time;
# mostly just the time you'll spend Googling for an implementation of MD4.
#
# You're thinking, why did we bother with this?
#
#   Blame Stripe. In their second CTF game, the second-to-last challenge
#   involved breaking an H(k, m) MAC with SHA1. Which meant that SHA1 code
#   was floating all over the Internet. MD4 code, not so much.
#
import inspect
import os
import random
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(inspect.getfile(lambda: 0)))))

from util.md4 import MD4

WORDS = [b"Aeaea", b"Aiea", b"Aia", b"Io", b"Eaio", b"Oea", b"ai", b"Aa"]


def md4_padding(msg, klen=0):
    ml_bytes = len(msg) + klen
    ml = ml_bytes * 8

    # Pre-processing: Total length is a multiple of 512 bits.
    padding = b"\x80"
    padding += b"\x00" * (-(ml_bytes + 9) % 64)
    padding += ml.to_bytes(8, "little")  # MD4 uses little-endian.

    return padding


def make_md4_pmac(msg, key):
    return MD4(key + msg)


def check_md4_pmac(msg, key, pmac):
    return MD4(key + msg) == pmac


def main():
    orig_msg = (
        b"comment1=cooking%20MCs;userdata=foo;"
        b"comment2=%20like%20a%20pound%20of%20bacon"
    )
    key = random.choice(WORDS)
    pmac = make_md4_pmac(orig_msg, key)

    print("First, let's verify that a message authenticates.")
    print()
    print("Message:      ", orig_msg)
    print("Key:          ", "<secret>")
    print("MAC:          ", pmac)
    print("Authenticates:", check_md4_pmac(orig_msg, key, pmac))
    print()
    print()
    print("Now for the attack.")

    extra_data = b";admin=true"

    crafted_pmac = MD4()  # Our result object.
    crafted_msg, h, key_length = b"", pmac.h.copy(), None

    # Since we don't know the key's bit length, we have to guess at it.
    for klen in range(1, 256):
        # Set "initial" state from original hash.
        crafted_pmac.h = h

        # The bit length of the key affects all of these.
        glue_padding = md4_padding(orig_msg, klen)
        crafted_msg = orig_msg + glue_padding + extra_data
        padded = extra_data + md4_padding(crafted_msg, klen)

        # Calculate hash of this particular crafted message.
        chunks = (padded[i : i + 64] for i in range(0, len(padded), 64))
        crafted_pmac._process(chunks)

        if check_md4_pmac(crafted_msg, key, crafted_pmac):
            key_length = klen
            break
    else:
        print("Unfortunately, we failed.")
        return

    print()
    print("Message:      ", crafted_msg)
    print("Key:          ", "<still secret>")
    print("Key length:   ", key_length)  # We guessed this.
    print("MAC:          ", crafted_pmac)
    print("Authenticates:", check_md4_pmac(crafted_msg, key, crafted_pmac))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


# Output;
#
#   First, let's verify that a message authenticates.
#
#   Message:       b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
#   Key:           <secret>
#   MAC:           344b1c7431e1361892d818ae2f906498
#   Authenticates: True
#
#
#   Now for the attack.
#
#   Message:       b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00x\x02\x00\x00\x00\x00\x00\x00;admin=true'
#   Key:           <still secret>
#   Key length:    2
#   MAC:           60885cb58c6818e111765c6dd15fb5f5
#   Authenticates: True
#
