#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Fixed XOR
#
# Write a function that takes two equal-length buffers and produces their XOR
# combination.
#
# If your function works properly, then when you feed it the string:
#
#   1c0111001f010100061a024b53535009181c
#
# ... after hex decoding, and when XOR'd against:
#
#   686974207468652062756c6c277320657965
#
# ... should produce:
#
#   746865206b696420646f6e277420706c6179
#
import inspect
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(inspect.getfile(lambda: 0)))))

def fixed_xor(hs1, hs2):
    hs1, hs2 = bytes.fromhex(hs1), bytes.fromhex(hs2)
    return bytes(c1 ^ c2 for c1, c2 in zip(hs1, hs2)).hex()


def main():
    print(
        fixed_xor(
            "1c0111001f010100061a024b53535009181c",
            "686974207468652062756c6c277320657965",
        )
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


# Output:
#
#   746865206b696420646f6e277420706c6179
#
