#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Break repeating-key XOR
#
# It is officially on, now.
#
#   This challenge isn't conceptually hard, but it involves actual
#   error-prone coding. The other challenges in this set are there to bring
#   you up to speed. This one is there to qualify you. If you can do this
#   one, you're probably just fine up to Set 6.
#
# There's a file here:
#
#   http://cryptopals.com/static/challenge-data/6.txt
#
# It's been base64'd after being encrypted with repeating-key XOR.
#
# Decrypt it.
#
# Here's how:
#
#   1. Let KEYSIZE be the guessed length of the key; try values from 2 to
#      (say) 40.
#   2. Write a function to compute the edit distance/Hamming distance between
#      two strings. The Hamming distance is just the number of differing
#      bits. The distance between:
#
#          this is a test
#
#      and
#
#          wokka wokka!!!
#
#      is 37. *Make sure your code agrees before you proceed.*
#   3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the
#      second KEYSIZE worth of bytes, and find the edit distance between them.
#      Normalize this result by dividing by KEYSIZE.
#   4. The KEYSIZE with the smallest normalized edit distance is probably the
#      key. You could proceed perhaps with the smallest 2-3 KEYSIZE values.
#      Or take 4 KEYSIZE blocks instead of 2 and average the distances.
#   5. Now that you probably know the KEYSIZE: break the ciphertext into
#      blocks of KEYSIZE length.
#   6. Now transpose the blocks: make a block that is the first byte of every
#      block, and a block that is the second byte of every block, and so on.
#   7. Solve each block as if it was single-character XOR. You already have
#      code to do this.
#   8. For each block, the single-byte XOR key that produces the best looking
#      histogram is the repeating-key XOR key byte for that block. Put them
#      together and you have the key.
#
# This code is going to turn out to be surprisingly useful later on. Breaking
# repeating-key XOR ("Vigenère") statistically is obviously an academic
# exercise, a "Crypto 101" thing. But more people "know how" to break it than
# can actually break it, and a similar technique breaks something much more
# important.
#
# No, that's not a mistake.
#
#   We get more tech support questions for this challenge than any of the
#   other ones. We promise, there aren't any blatant errors in this text.
#   In particular: the "wokka wokka!!!" edit distance really is 37.
#
import sys
from itertools import zip_longest

sys.path.append("..")

from util.loader import loader
from util.text import englishness, repeating_key_xor, single_byte_xor


# Lookup table for the number of 1 bits in a nibble. (Nybble, quartet, etc.)
NIBBLE_BITS = [0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4]


def likely_key_sizes(bs, lower=2, upper=40, n=3):
    """Finds a repeating-key-XOR'd ciphertext's most likely key sizes."""
    sizes = {}

    for size in range(lower, upper + 1):
        normalized_distance = 0

        for i in range(0, len(bs) - size * 2, size * 2):
            bs1, bs2 = bs[i : i + size], bs[i + size : i + size * 2]
            normalized_distance += hamming_distance(bs1, bs2) / 2

        sizes.update({size: normalized_distance})

    return sorted(sizes, key=lambda k: sizes[k])[:n]


def hamming_distance(bs1, bs2):
    """Finds the Hamming distance between two bytestrings."""
    distance = 0

    for b1, b2 in zip_longest(bs1, bs2, fillvalue=0):
        b = b1 ^ b2
        distance += NIBBLE_BITS[b >> 4] + NIBBLE_BITS[b & 0xF]

    return distance


def main():
    ctext = loader("6.txt", "base64", split=False)

    ptext, key, high_score = b"", b"", 0

    for size in likely_key_sizes(ctext):
        blocks = [ctext[i : i + size] for i in range(0, len(ctext), size)]
        transposed = zip_longest(*blocks, fillvalue=0)

        likely_key = b"".join(
            single_byte_xor(tblock, key=True) for tblock in transposed
        )

        candidate = repeating_key_xor(ctext, likely_key)
        score = englishness(candidate)

        if score > high_score:
            ptext, key, high_score = candidate, likely_key, score

    print(f"Key: '{key.decode()}'")
    print()
    print(ptext.decode())


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


# Output:
#
#   Key: 'Terminator X: Bring the noise' (29 bytes)
#
#   I'm back and I'm ringin' the bell
#   A rockin' on the mike while the fly girls yell
#   In ecstasy in the back of me
#   Well that's my DJ Deshay cuttin' all them Z's
#   Hittin' hard and the girlies goin' crazy
#   Vanilla's on the mike, man I'm not lazy.
#
#   <remainder of output omitted>
#
