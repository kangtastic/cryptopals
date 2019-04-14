#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# The CBC padding oracle
#
# This is the best-known attack on modern block-cipher cryptography.
#
# Combine your padding code and your CBC code to write two functions.
#
# The first function should select at random one of the following 10 strings:
#
#   MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
#   MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
#   MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
#   MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
#   MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
#   MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
#   MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
#   MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
#   MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
#   MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93
#
# ... generate a random AES key (which it should save for all future
# encryptions), pad the string out to the 16-byte AES block size and
# CBC-encrypt it under that key, providing the caller the ciphertext and IV.
#
# The second function should consume the ciphertext produced by the first
# function, decrypt it, check its padding, and return true or false depending
# on whether the padding is valid.
#
# What you're doing here:
#
#   This pair of functions approximates AES-CBC encryption as it's deployed
#   serverside in web applications; the second function models the server's
#   consumption of an encrypted session token, as if it was a cookie.
#
# It turns out that it's possible to decrypt the ciphertexts provided by the
# first function.
#
# The decryption here depends on a side-channel leak by the decryption
# function. The leak is the error message that the padding is valid or not.
#
# You can find 100 web pages on how this attack works, so I won't re-explain
# it. What I'll say is this:
#
# The fundamental insight behind this attack is that the byte 01h is valid
# padding, and occur in 1/256 trials of "randomized" plaintexts produced by
# decrypting a tampered ciphertext.
#
# 02h in isolation is *not* valid padding.
#
# 02h 02h *is* valid padding, but is much less likely to occur randomly than
# 01h.
#
# 03h 03h 03h is even less likely.
#
# So you can assume that if you corrupt a decryption AND it had valid padding,
# you know what that padding byte is.
#
# It is easy to get tripped up on the fact that CBC plaintexts are "padded".
# *Padding oracles have nothing to do with the actual padding on a CBC
# plaintext.* It's an attack that targets a specific bit of code that handles
# decryption. You can mount a padding oracle on *any CBC block*, whether it's
# padded or not.
#
import base64
import inspect
import os
import random
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(inspect.getfile(lambda: 0)))))

from util.aes import aes_cbc_decrypt, aes_cbc_encrypt, make_aes_key
from util.text import unpad_pkcs7

KEY = b""
B64STRS = [
    b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
]


def submit_random_ptext():
    global KEY
    KEY, iv = make_aes_key(), make_aes_key()
    ptext = base64.b64decode(random.choice(B64STRS))
    ctext = aes_cbc_encrypt(ptext, KEY, iv)
    return ctext, iv


def oracle(ctext, iv):
    ptext = aes_cbc_decrypt(ctext, KEY, iv, unpad=False)
    try:
        unpad_pkcs7(ptext, assume_padded=True)
    except ValueError:
        return False
    else:
        return True


def attack_aes_cbc_block(block, prev):
    ptext = itext = b""

    for i, j in enumerate(range(15, -1, -1), 1):
        left, right = prev[:j], bytes(b ^ i for b in itext)

        for n in range(256):
            fake_ivs = [left + bytes([n]) + right]
            if len(left) > 1:
                left_ = left[:-1] + bytes([left[-1] ^ 0xAA])
                fake_ivs.append(left_ + bytes([n]) + right)

            if not all(oracle(block, fake_iv) for fake_iv in fake_ivs):
                continue

            itext = bytes([n ^ i]) + itext
            ptext = bytes([n ^ i ^ prev[j]]) + ptext

            break

    return ptext


def main():
    ctext, iv = submit_random_ptext()

    ptext, prev = b"", iv

    for i in range(0, len(ctext), 16):
        block = ctext[i : i + 16]
        ptext += attack_aes_cbc_block(block, prev)
        prev = block

    ptext = unpad_pkcs7(ptext)

    print(ptext.decode())


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


# Output:
#
#   000000Now that the party is jumping
#
