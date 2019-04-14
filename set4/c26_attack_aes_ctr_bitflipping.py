#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# CTR bitflipping
#
# There are people in the world that believe that CTR resists bit flipping
# attacks of the kind to which CBC mode is susceptible.
#
# Re-implement the CBC bitflipping exercise from earlier:
#
#   http://cryptopals.com/sets/2/challenges/16
#
# to use CTR mode instead of CBC mode. Inject an "admin=true" token.
import random
import sys

sys.path.append("..")

from util.aes import aes_ctr, make_aes_key

KEY = make_aes_key()
NONCE = random.getrandbits(64)
PREFIX = b"comment1=cooking%20MCs;userdata="
POSTFIX = b";comment2=%20like%20a%20pound%20of%20bacon"


def make_userdata(bs):
    userdata = bs.replace(b";", b"';'").replace(b"=", b"'='")
    ptext = PREFIX + userdata + POSTFIX
    return aes_ctr(ptext, KEY, NONCE)


def is_admin(ctext):
    if b";admin=true;" in aes_ctr(ctext, KEY, NONCE):
        return True
    return False


def main():
    # `make_userdata()` will be encrypting the following:
    #   b'comment1=cooking%20MCs;userdata=laffo\x00admin\xfftrue;comment2=...'
    ctext = make_userdata(b"laffo\x00admin\xfftrue")

    print("Original ciphertext gives admin:", is_admin(ctext))

    # 0x00 and 0xff end up in positions 37 and 43 of the plaintext. It should
    # be clear that these values don't matter; we just need to know them.
    crafted_ctext = bytearray(ctext)
    crafted_ctext[37] ^= ord(";")  # ^ 0x00
    crafted_ctext[43] ^= ord("=") ^ 0xFF

    print("Crafted ciphertext gives admin: ", is_admin(crafted_ctext))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass

# Output:
#
#   Original ciphertext gives admin: False
#   Crafted ciphertext gives admin:  True
#
