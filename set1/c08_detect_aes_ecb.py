#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Detect AES in ECB mode
#
# In this file:
#
#   http://cryptopals.com/static/challenge-data/8.txt
#
# are a bunch of hex-encoded ciphertexts.
#
# One of them has been encrypted with ECB.
#
# Detect it.
#
# Remember that the problem with ECB is that it is stateless and
# deterministic; the same 16 byte plaintext block will always produce the
# same 16-byte ciphertext.
#
import inspect
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(inspect.getfile(lambda: 0)))))

from util.aes_wrappers import is_aes_ecb
from util.loader import loader


def main():
    cdata = loader("8.txt", "base64")
    aes_ecb_lines = [n for n, ctext in enumerate(cdata, 1) if is_aes_ecb(ctext)]
    print("The following lines were encrypted with AES-ECB:", aes_ecb_lines)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


# Output:
#
#   The following lines were encrypted with AES-ECB: [133]
#
