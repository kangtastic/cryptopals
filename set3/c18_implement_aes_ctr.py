#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Implement CTR, the stream cipher mode
#
# The string:
#
#   L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==
#
# ... decrypts to something approximating English in CTR mode, which is an AES
# block cipher mode that turns AES into a stream cipher, with the following
# parameters:
#
#   key=YELLOW SUBMARINE
#   nonce=0
#   format=64 bit unsigned little endian nonce,
#          64 bit little endian block count (byte count / 16)
#
# CTR mode is very simple.
#
# Instead of encrypting the plaintext, CTR mode encrypts a running counter,
# producing a 16 byte block of keystream, which is XOR'd against the
# plaintext.
#
# For instance, for the first 16 bytes of a message with these parameters:
#
#   keystream = AES("YELLOW SUBMARINE",
#                   "\x00\x00\x00\x00\x00\x00\x00\x00"
#                   "\x00\x00\x00\x00\x00\x00\x00\x00")
#
# ... for the next 16 bytes:
#
#   keystream = AES("YELLOW SUBMARINE",
#                   "\x00\x00\x00\x00\x00\x00\x00\x00"
#                   "\x01\x00\x00\x00\x00\x00\x00\x00")
#
# ... and then:
#
#   keystream = AES("YELLOW SUBMARINE",
#                   "\x00\x00\x00\x00\x00\x00\x00\x00"
#                   "\x02\x00\x00\x00\x00\x00\x00\x00")
#
# CTR mode does not require padding; when you run out of plaintext, you just
# stop XOR'ing keystream and stop generating keystream.
#
# Decryption is identical to encryption. Generate the same keystream, XOR, and
# recover the plaintext.
#
# Decrypt the string at the top of this function, then use your CTR function
# to encrypt and decrypt other things.
#
# This is the only block cipher mode that matters in good code.
#
#   Most modern cryptography relies on CTR mode to adapt block ciphers into
#   stream ciphers, because most of what we want to encrypt is better
#   described as a stream than as a sequence of blocks. Daniel Bernstein once
#   quipped to Phil Rogaway that good cryptosystems don't need the "decrypt"
#   transforms. Constructions like CTR are what he was talking about.
#
import base64
import inspect
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(inspect.getfile(lambda: 0)))))

from util.aes_wrappers import aes_ctr

KEY = b"YELLOW SUBMARINE"
B64STR = b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
NONCE = 0


def main():
    ctext = base64.b64decode(B64STR)
    ptext = aes_ctr(ctext, KEY, NONCE)
    print(ptext.decode())


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


# Output:
#
#   Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby
#
