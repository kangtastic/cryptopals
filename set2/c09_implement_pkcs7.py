#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Implement PKCS#7 padding
#
# A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of
# plaintext into ciphertext. But we almost never want to transform a single
# block; we encrypt irregularly-sized messages.
#
# One way we account for irregularly-sized messages is by padding, creating
# a plaintext that is an even multiple of the blocksize. The most popular
# padding scheme is called PKCS#7.
#
# So: pad any block to a specific block length, by appending the number of
# bytes of padding to the end of the block.
#
# For instance,
#
#   "YELLOW SUBMARINE"
#
# ... padded to 20 bytes would be:
#
#   "YELLOW SUBMARINE\x04\x04\x04\x04"
#
import sys

sys.path.append("..")

from util.text import pad_pkcs7


def main():
    text = b"YELLOW SUBMARINE"
    print("Some text:    ", text)
    print("PKCS#7 padded:", pad_pkcs7(text, 20))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


# Output:
#
#   Some text:     b'YELLOW SUBMARINE'
#   PKCS#7 padded: b'YELLOW SUBMARINE\x04\x04\x04\x04'
#
