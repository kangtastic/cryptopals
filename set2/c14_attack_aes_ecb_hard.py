#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Byte-at-a-time ECB decryption (Harder)
#
# Take your oracle function from #12. Now generate a random count of random
# bytes and prepend this string to every plaintext.
#
# You are now doing:
#
#   AES-128-ECB(random-prefix || attacker-controlled || target-bytes,
#               random-key)
#
# Same goal: decrypt the target-bytes.
#
# Stop and think for a second.
#
#   What's harder than challenge #12 about doing this? How would you overcome
#   that obstacle? The hint is: you're using all the tools you already have; no
#   crazy math is required.
#
#   Think "STIMULUS" and "RESPONSE".
#
import base64
import inspect
import os
import random
import sys
from collections import Counter
from itertools import islice

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(inspect.getfile(lambda: 0)))))

from util.aes_wrappers import aes_ecb_encrypt, make_aes_key

KEY = make_aes_key()
PREFIX = bytes(random.getrandbits(8) for _ in range(random.randrange(16)))
POSTFIX = base64.b64decode(
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
    "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
    "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
    "YnkK"
)


def oracle(ptext):
    ptext = ptext.encode() if isinstance(ptext, str) else ptext
    return aes_ecb_encrypt(PREFIX + ptext + POSTFIX, KEY)


def chunks(iterable, size):
    func, gen = type(iterable), (item for item in iterable)
    chunk = func(islice(gen, size))
    while chunk:
        yield chunk
        chunk = func(islice(gen, size))


def find_prepad_len(bsize=16, nreps=2):
    ptext = b"A" * bsize * nreps
    for pplen in range(bsize):
        ctext = oracle(b"Z" * pplen + ptext)
        ctr = Counter(chunks(ctext, bsize))
        most_reps = ctr.most_common(1)[0][1]
        if most_reps == nreps:
            return pplen


def attack_aes_ecb_hard(bsize=16):
    prepad = b"Z" * find_prepad_len()
    lpads = [b"A" * (bsize - i - 1) for i in range(bsize)]
    ctexts = [oracle(prepad + lpad) for lpad in lpads]

    blocks, finished = [], False

    while not finished:
        next_blk, start = b"", bsize * (len(blocks) + 1)

        for i in range(bsize):
            lpad = blocks[-1][i + 1 :] if blocks else lpads[i]
            ptext, ct_blk = lpad + next_blk, ctexts[i][start : start + bsize]

            # Alternative: Create a dictionary of all possible last bytes
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
    unknown_string = attack_aes_ecb_hard()
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
#   Unknown string:
#
#   Rollin' in my 5.0
#   With my rag-top down so my hair can blow
#   The girlies on standby waving just to say hi
#   Did you stop? No, I just drove by
#
