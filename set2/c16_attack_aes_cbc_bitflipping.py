#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# CBC bitflipping attacks
#
# Generate a random AES key.
#
# Combine your padding code and CBC code to write two functions.
#
# The first function should take an arbitrary input string, prepend the string:
#
#   "comment1=cooking%20MCs;userdata="
#
# .. and append the string:
#
#   ";comment2=%20like%20a%20pound%20of%20bacon"
#
# The function should quote out the ";" and "=" characters.
#
# The function should then pad out the input to the 16-byte AES block length
# and encrypt it under the random AES key.
#
# The second function should decrypt the string and look for the characters
# ";admin=true;" (or, equivalently, decrypt, split the string on ";", convert
# each resulting string into 2-tuples, and look for the "admin" tuple).
#
# Return true or false based on whether the string exists.
#
# If you've written the first function properly, it should *not* be possible to
# provide user input to it that will generate the string the second function
# is looking for. We'll have to break the crypto to do that.
#
# Instead, modify the ciphertext (without knowledge of the AES key) to
# accomplish this.
#
# You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext
# block:
#
# - Completely scrambles the block the error occurs in
# - Produces the identical 1-bit error(/edit) in the next ciphertext block.
#
# Stop and think for a second.
#
#   Before you implement this attack, answer this question: why does CBC mode
#   have this property?
#
import sys

sys.path.append("..")

from util.aes import aes_cbc_decrypt, aes_cbc_encrypt, make_aes_key
from util.text import repeating_key_xor

# Key and IV are both 128 random bits.
KEY = make_aes_key()
IV = make_aes_key()
PREFIX = b"comment1=cooking%20MCs;userdata="
POSTFIX = b";comment2=%20like%20a%20pound%20of%20bacon"


def make_userdata(bs):
    userdata = bs.replace(b";", b"';'").replace(b"=", b"'='")
    ptext = PREFIX + userdata + POSTFIX
    return aes_cbc_encrypt(ptext, KEY, IV)


def is_admin(ctext):
    if b";admin=true;" in aes_cbc_decrypt(ctext, KEY, IV):
        return True
    return False


def main():
    # `make_userdata()` will be encrypting the following:
    # b"comment1=cooking%20MCs;userdata=[32 NUL bytes];comment2=...".
    # It's convenient, but not strictly necessary, that
    # b"comment1=cooking%20MCs;userdata=" is 2 blocks long.
    ctext = make_userdata(b"\x00" * 32)

    # Corrupt the 3rd block in the ciphertext, which corresponds to the first
    # 16 NUL bytes in the plaintext, by XORing it with b"LAFFO;admin=true"
    # (which itself has length 16).
    block3 = repeating_key_xor(ctext[32:48], b"LAFFO;admin=true")

    # Decrypting this corrupted ciphertext will then result in:
    # b"...%20MCs;userdata=[16 rubbish bytes]LAFFO;admin=true;comment2=...".
    # The 4th block, which would have been all NULs, becomes the XOR of
    # those NULs and the corrupted 3rd block.
    crafted_ctext = ctext[:32] + block3 + ctext[48:]

    print("Original ciphertext gives admin:", is_admin(ctext))
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
