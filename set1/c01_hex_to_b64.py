#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Convert hex to base64
#
# The string:
#
#   49276d206b696c6c696e6720796f757220627261696e206c
#   696b65206120706f69736f6e6f7573206d757368726f6f6d
#
# should produce:
#
# SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
#
import sys

sys.path.append("..")

from util.text import hexstring_to_b64


def main():
    print(
        hexstring_to_b64(
            "49276d206b696c6c696e6720796f757220627261696e206c"
            "696b65206120706f69736f6e6f7573206d757368726f6f6d"
        ).decode()
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


# Output:
#
#   SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
#
