#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# AES in ECB mode
#
# The Base64-encoded content in this file:
#
#   http://cryptopals.com/static/challenge-data/7.txt
#
# has been encrypted via AES-128 in ECB mode under the key:
#
#   "YELLOW SUBMARINE".
#
# (case-sensitive, without the quotes; exactly 16 characters; I like
# "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).
#
# Decrypt it. You know the key, after all.
#
# Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.
#
import inspect
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(inspect.getfile(lambda: 0)))))

from util.aes_wrappers import aes_ecb_decrypt
from util.loader import loader


def main():
    key = b"YELLOW SUBMARINE"
    ctext = loader("7.txt", "base64", split=False)
    ptext = aes_ecb_decrypt(ctext, key)

    print(ptext.decode())


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


# Output:
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
