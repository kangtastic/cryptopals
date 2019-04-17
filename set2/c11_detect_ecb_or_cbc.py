#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# An ECB/CBC detection oracle
#
# Now that you have ECB and CBC working:
#
# Write a function to generate a random AES key; that's just 16 random bytes.
#
# Write a function that encrypts data under an unknown key --- that is, a
# function that generates a random key and encrypts under it.
#
# The function should look like:
#
#   encryption_oracle(your-input)
#     => [MEANINGLESS JIBBER JABBER]
#
# Under the hood, have the function append 5-10 bytes (count chosen randomly)
# before the plaintext and 5-10 bytes after the plaintext.
#
# Now, have the function choose to encrypt under ECB 1/2 the time, and under
# CBC the other half (just use random IVs each time for CBC). Use rand(2) to
# decide which to use.
#
# Detect the block cipher mode the function is using each time. You should
# end up with a piece of code that, pointed at a block box that might be
# encrypting ECB or CBC, tells you which one is happening.
#
import inspect
import os
import random
import sys
from string import ascii_letters

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(inspect.getfile(lambda: 0)))))

from util.aes_wrappers import aes_cbc_encrypt, aes_ecb_encrypt, make_aes_key, is_aes_ecb


def oracle(ptext):
    key, ecb_mode = make_aes_key(), random.getrandbits(1)

    pre = bytes(random.getrandbits(8) for _ in range(random.randint(5, 10)))
    post = bytes(random.getrandbits(8) for _ in range(random.randint(5, 10)))

    ptext = pre + ptext + post

    if ecb_mode:
        ctext = aes_ecb_encrypt(ptext, key)
    else:
        iv = make_aes_key()
        ctext = aes_cbc_encrypt(ptext, key, iv)

    return ctext, ecb_mode


def main():
    # Detection is unreliable for short inputs, which is probably the point.
    print("Generating, encrypting, and detecting 5 random plaintexts.")
    print("These consist of a single ASCII letter repeated 1-128 times.")
    print()

    failures = []

    for _ in range(10):
        pt_length = random.randint(1, 128)
        ptext = bytes(map(ord, random.choice(ascii_letters) * pt_length))

        ctext, actual = oracle(ptext)
        guess = is_aes_ecb(ctext)

        if actual != guess:
            failures.append(pt_length)

    if failures:
        print("Guessed wrongly for the following lengths:", failures)
    else:
        print("No wrong guesses.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


# Output:
#
#   Generating, encrypting, and detecting 5 random plaintexts.
#   These consist of a single ASCII letter repeated 1-128 times.
#
#   Guessed wrongly for the following lengths: [24, 34]
#
