#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Single-byte XOR cipher
#
# The hex encoded string:
#
#   1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
#
# ... has been XOR'd against a single character.
#
# Find the key, decrypt the message.
#
# You can do this by hand. But don't: write code to do it for you.
#
# How? Devise some method for "scoring" a piece of English plaintext.
# Character frequency is a good metric. Evaluate each output and choose the
# one with the best score.
#
import sys

sys.path.append("..")

from util.text import single_byte_xor


HEXSTRING = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"


def main():
    ctext = bytes.fromhex(HEXSTRING)
    ptext = single_byte_xor(ctext)
    print(ptext.decode())


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass

# Output:
#
#   Cooking MC's like a pound of bacon
#
