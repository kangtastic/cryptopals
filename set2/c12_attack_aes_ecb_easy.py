#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Byte-at-a-time ECB decryption (Simple)
#
# Copy your oracle function to a new function that encrypts buffers under ECB
# mode using a consistent but unknown key (for instance, assign a single random
# key, once, to a global variable).
#
# Now take that same function and have it append to the plaintext, BEFORE
# ENCRYPTING, the following string:
#
#   Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
#   aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
#   dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
#   YnkK
#
# Spoiler alert:
#   Do not decode this string now. Don't do it.
#
# Base64 decode the string before appending it. Do not base64 decode the string
# by hand; make your code do it. The point is that you don't know its contents.
#
# What you have now is a function that produces:
#
#   AES-128-ECB(your-string || unknown-string, random-key)
#
# It turns out: you can decrypt "unknown-string" with repeated calls to the
# oracle function!
#
# Here's roughly how:
#
#   1. Feed identical bytes of your-string to the function 1 at a time ---
#      start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the
#      block size of the cipher. You know it, but do this step anyway.
#   2. Detect that the function is using ECB. You already know, but do this
#      step anyways.
#   3. Knowing the block size, craft an input block that is exactly 1 byte
#      short (for instance, if the block size is 8 bytes, make "AAAAAAA").
#      Think about what the oracle function is going to put in that last byte
#      position.
#   4. Make a dictionary of every possible last byte by feeding different
#      strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB",
#      "AAAAAAAC", remembering the first block of each invocation.
#   5. Match the output of the one-byte-short input to one of the entries in
#      your dictionary. You've now discovered the first byte of unknown-string.
#   6. Repeat for the next byte.
#
import base64
import inspect
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(inspect.getfile(lambda: 0)))))

from util.aes_wrappers import aes_ecb_encrypt, make_aes_key, is_aes_ecb

KEY = make_aes_key()
POSTFIX = base64.b64decode(
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
    "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
    "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
    "YnkK"
)


def oracle(ptext):
    ptext = ptext.encode() if isinstance(ptext, str) else ptext
    return aes_ecb_encrypt(ptext + POSTFIX, KEY)


def find_block_size():
    bsize, ct_len = 0, len(oracle(b""))

    for block_boundary_found in range(2):  # i.e. 0 or 1.
        for n in range(1, 1025):  # 1025 is just a high number.
            new_len = len(oracle(b"A" * (n + bsize)))
            if new_len != ct_len:
                if block_boundary_found:
                    return n
                else:
                    bsize, ct_len = n, new_len
                    break

    return 0


def attack_aes_ecb_easy(bsize):
    lpads = [b"A" * (bsize - i - 1) for i in range(bsize)]
    ctexts = [oracle(lpad) for lpad in lpads]

    blocks, finished = [], False

    while not finished:
        next_blk, start = b"", bsize * len(blocks)

        for i in range(bsize):
            lpad = blocks[-1][i + 1 :] if blocks else lpads[i]
            ptext, ct_blk = lpad + next_blk, ctexts[i][start : start + bsize]

            # Alternative: Create a dictionary of all possible last bytes.
            # next_b = {aes_ecb_encrypt(ptext + bytes([n]), KEY):
            #           bytes([n]) for n in range(256)}
            #
            # next_blk += next_b[ct_blk]

            for b in map(lambda n: bytes([n]), range(256)):
                if aes_ecb_encrypt(ptext + b, KEY) == ct_blk:
                    next_blk += b
                    break

            pad = next_blk[-1]
            if 0 < pad < bsize and sum(next_blk[-pad:]) == (pad ** 2):
                next_blk, finished = next_blk[:-pad], True
                break

        blocks.append(next_blk)

    return b"".join(blocks)


def main():
    bsize = find_block_size()
    using_aes_ecb = is_aes_ecb(oracle(b"A" * bsize * 2))

    print(f"Block size: {bsize}")
    print(f"Using AES-ECB: {using_aes_ecb}")
    print()

    if not using_aes_ecb:
        return

    unknown_string = attack_aes_ecb_easy(bsize)
    print("Unknown string:")
    print()
    print(unknown_string.decode())


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass

# Output:
#
#   Block size: 16
#   Using AES-ECB: True
#
#   Unknown string:
#
#   Rollin' in my 5.0
#   With my rag-top down so my hair can blow
#   The girlies on standby waving just to say hi
#   Did you stop? No, I just drove by
#
