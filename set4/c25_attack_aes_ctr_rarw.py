#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Break "random access read/write" AES-CTR
#
# Back to CTR. Encrypt the recovered plaintext from this file:
#
#   http://cryptopals.com/static/challenge-data/25.txt
#
# (the ECB exercise) under CTR with a random key (for this exercise the key
# should be unknown to you, but hold on to it).
#
# Now, write the code that allows you to "seek" into the ciphertext, decrypt,
# and re-encrypt with different plaintext. Expose this as a function, like,
# "*edit(ciphertext, key, offset, newtext)*".
#
# Imagine the "edit" function was exposed to attackers by means of an API
# call that didn't reveal the key or the original plaintext; the attacker has
# the ciphertext and controls the offset and "new text".
#
# Recover the original plaintext.
#
# Food for thought.
#
#   A folkloric supposed benefit of CTR mode is the ability to easily "seek
#   forward" into the ciphertext; to access byte N of the ciphertext, all you
#   need to be able to do is generate byte N of the keystream. Imagine if
#   you'd relied on that advice to, say, encrypt a disk.
#
import inspect
import os
import signal
import sys
from multiprocessing import Pool

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(inspect.getfile(lambda: 0)))))

from util.aes_wrappers import aes_ctr, aes_ecb_decrypt, make_aes_key
from util.misc import cpu_threads
from util.loader import loader

CPUS = cpu_threads()


def edit(ctext, key, offset, ntext):
    edited_ptext = aes_ctr(ctext[:offset], key) + ntext
    return aes_ctr(edited_ptext, key)


def mp_find_ptext_byte(mp_data, width=48, char="\u2588"):
    ctext, key, offset = mp_data

    pos, ct_len = offset + 1, len(ctext)
    pct = pos * 100 // ct_len
    bar = (char * (pos * width // ct_len)).ljust(width)
    print(f"\r[{bar}] {pct}% ({pos}/{ct_len})", end="", flush=True)

    for n in range(256):
        ct_byte = edit(ctext[:offset], key, offset, bytes([n]))[offset]
        if ct_byte == ctext[offset]:
            return n


def main():
    ecb_key, key = b"YELLOW SUBMARINE", make_aes_key()
    ptext = aes_ecb_decrypt(loader("25.txt", "base64", split=False), ecb_key)
    ctext = aes_ctr(ptext, key)

    print(f"Cracking ciphertext using {CPUS} cores, please wait.")

    # This signal handler business allows Ctrl-C to work more gracefully
    # with multiprocessing. (Tested on Linux only.)
    orig_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
    with Pool(CPUS) as pool:
        signal.signal(signal.SIGINT, orig_handler)

        mp_data = ((ctext, key, offset) for offset in range(len(ctext)))
        try:
            recovered_ptext = bytes(pool.imap(mp_find_ptext_byte, mp_data))
        except KeyboardInterrupt:
            raise
        else:
            print()
            print(recovered_ptext.decode())
        finally:
            print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


# Output:
#
#   Cracking ciphertext using 11 cores, please wait.
#   [████████████████████████████████████████████████] 100% (2876/2876)
#
#   I'm back and I'm ringin' the bell
#   A rockin' on the mike while the fly girls yell
#   In ecstasy in the back of me
#   Well that's my DJ Deshay cuttin' all them Z's
#   Hittin' hard and the girlies goin' crazy
#   Vanilla's on the mike, man I'm not lazy.
#
#   <remaining output omitted>
#
