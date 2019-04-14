#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Detect single-character XOR
#
# One of the 60-character strings in this file:
#
#   http://cryptopals.com/static/challenge-data/4.txt
#
# has been encrypted by single-character XOR.
#
# Find it.
#
# (Your code from #3 should help.)
#
import sys

sys.path.append("..")

from util.loader import loader
from util.text import englishness, single_byte_xor


def main():
    ptext, high_score = b"", 0

    for ctext in loader("4.txt", "hexstring"):
        candidate = single_byte_xor(ctext)
        score = englishness(candidate)
        if score > high_score:
            ptext, high_score = candidate, score

    print(ptext.decode())


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass

# Output:
#
#   Now that the party is jumping
#
#
