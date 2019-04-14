#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# PKCS#7 padding validation
#
# Write a function that takes a plaintext, determines if it has valid PKCS#7
# padding, and strips the padding off.
#
# The string:
#
#   "ICE ICE BABY\x04\x04\x04\x04"
#
# ... has valid padding, and produces the result "ICE ICE BABY".
#
# The string:
#
# "ICE ICE BABY\x05\x05\x05\x05"
#
# ... does not have valid padding, nor does:
#
# "ICE ICE BABY\x01\x02\x03\x04"
#
# If you are writing in a language with exceptions, like Python or Ruby, make
# your function throw an exception on bad padding.
#
# Crypto nerds know where we're going with this. Bear with us.
#
import inspect
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(inspect.getfile(lambda: 0)))))

from util.text import unpad_pkcs7


def main():
    ptexts = [
        b"ICE ICE BABY\x04\x04\x04\x04",
        b"ICE ICE BABY\x05\x05\x05\x05",
        b"ICE ICE BABY\x01\x02\x03\x04",
    ]

    for ptext in ptexts:
        try:
            unpad_pkcs7(ptext)
        except ValueError:
            valid = False
        else:
            valid = True

        print(f"{ptext} is padded PKCS#7: {valid}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


# Output:
#
#   b'ICE ICE BABY\x04\x04\x04\x04' is padded PKCS#7: True
#   b'ICE ICE BABY\x05\x05\x05\x05' is padded PKCS#7: False
#   b'ICE ICE BABY\x01\x02\x03\x04' is padded PKCS#7: False
#
