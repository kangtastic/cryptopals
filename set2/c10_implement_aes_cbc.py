#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Implement CBC mode
#
# CBC mode is a block cipher mode that allows us to encrypt irregularly-sized
# messages, despite the fact that a block cipher natively only transforms
# individual blocks.
#
# In CBC mode, each ciphertext block is added to the next plaintext block
# before the next call to the cipher core.
#
# The first plaintext block, which has no associated previous ciphertext
# block, is added to a "fake 0th ciphertext block" called the initialization
# vector, or IV.
#
# Implement CBC mode by hand by taking the ECB function you wrote earlier,
# making it encrypt instead of decrypt (verify this by decrypting whatever
# you encrypt to test), and using your XOR function from the previous
# exercise to combine them.
#
# The file here:
#
#   http://cryptopals.com/static/challenge-data/10.txt
#
# is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE"
# with an IV of all ASCII 0 (\x00\x00\x00 &c).
#
import inspect
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(inspect.getfile(lambda: 0)))))

from util.aes_wrappers import aes_cbc_decrypt
from util.loader import loader


def main():
    key = b"YELLOW SUBMARINE"
    ctext = loader("10.txt", "base64", split=False)
    ptext = aes_cbc_decrypt(ctext, key)

    print("Decrypted a ciphertext AES-CBC.")
    print("Used a null IV and the following key:", key)
    print()

    print(ptext.decode())
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


# Output:
#
#   Decrypted a ciphertext AES-CBC.
#   Used a null IV and the following key: b'YELLOW SUBMARINE'
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
