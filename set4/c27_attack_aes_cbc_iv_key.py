#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Recover the key from CBC with IV=Key
#
# Take your code from the CBC exercise:
#
#   http://cryptopals.com/sets/2/challenges/16
#
# and modify it so that it repurposes the key for CBC encryption as the IV.
#
# Applications sometimes use the key as an IV on the auspices that both the
# sender and the receiver have to know the key already, and can save some
# space by using it as both a key and an IV.
#
# Using the key as an IV is insecure; an attacker that can modify ciphertext
# in flight can get the receiver to decrypt a value that will reveal the key.
#
# The CBC code from exercise 16 encrypts a URL string. Verify each byte of
# the plaintext for ASCII compliance (ie, look for high-ASCII values).
# Noncompliant messages should raise an exception or return an error that
# includes the decrypted plaintext (this happens all the time in real
# systems, for what it's worth).
#
# Use your code to encrypt a message that is at least 3 blocks long:
#
#   AES-CBC(P_1, P_2, P_3) -> C_1, C_2, C_3
#
# Modify the message (you are now the attacker):
#
#   C_1, C_2, C_3 -> C_1, 0, C_1
#
# Decrypt the message (you are now the receiver) and raise the appropriate
# error if high-ASCII is found.
#
# As the attacker, recovering the plaintext from the error, extract the key:
#
#   P'_1 XOR P'_3
#
import sys

sys.path.append("..")

from util.aes import aes_cbc_decrypt, aes_cbc_encrypt, make_aes_key
from util.text import to_hexstring

KEY = make_aes_key()
PTEXT = b"This is a plaintext having a length of at least 48 characters."


class NotASCIIError(Exception):
    def __init__(self, bs, offset):
        self.bs = bs
        self.offset = offset

    def __repr__(self):
        return f"{self.__class__.__name__}({self.bs:s}, {self.offset})"

    def __str__(self):
        return f"non-ASCII value in {self.bs:s} at offset {self.offset}"


def encrypt_message(ptext):
    return aes_cbc_encrypt(ptext, KEY, iv=KEY)


def decrypt_message(ctext):
    ptext = aes_cbc_decrypt(ctext, KEY, iv=KEY)
    try:
        check_ascii(ptext)
    except NotASCIIError:
        raise
    return ptext


def check_ascii(ptext):
    if isinstance(ptext, str):
        ptext = ptext.encode()
    for i in range(len(ptext)):
        if ptext[i] & 0x80:
            raise NotASCIIError(ptext, i)


def main():
    print("Original AES key: ", to_hexstring(KEY))

    ctext = encrypt_message(PTEXT)

    crafted_ctext = ctext[:16] + b"\x00" * 16 + ctext[:16]
    recovered_key = b""

    try:
        decrypt_message(crafted_ctext)
    except NotASCIIError as e:
        p_1, p_3 = e.bs[:16], e.bs[32:48]
        recovered_key = bytes(p_1b ^ p_3b for p_1b, p_3b in zip(p_1, p_3))

    print("Recovered AES key:", to_hexstring(recovered_key))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


# Output:
#
#   Original AES key:  cabba09b96b37540761b8db848adf51f
#   Recovered AES key: cabba09b96b37540761b8db848adf51f
#
