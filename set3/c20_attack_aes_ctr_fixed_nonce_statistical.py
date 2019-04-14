#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Break fixed-nonce CTR statistically
#
# In this file:
#
#   http://cryptopals.com/static/challenge-data/20.txt
#
# find a similar set of Base64'd plaintext. Do with them exactly what you did
# with the first, but solve the problem differently.
#
# Instead of making spot guesses as to known plaintext, treat the collection of
# ciphertexts the same way you would repeating-key XOR.
#
# Obviously, CTR encryption appears different from repeated-key XOR, *but with
# a fixed nonce they are effectively the same thing.*
#
# To exploit this: take your collection of ciphertexts and truncate them to a
# common length (the length of the smallest ciphertext will work).
#
# Solve the resulting concatenation of ciphertexts as if for repeating-key XOR,
# with a key size of the length of the ciphertext you XOR'd.
#
import sys

sys.path.append("..")

from set3.c19_attack_aes_ctr_fixed_nonce_substitution import guess_keystream
from util.aes import aes_ctr, make_aes_key
from util.loader import loader
from util.text import repeating_key_xor

KEY = make_aes_key()
NONCE = 0


# We solved the previous challenge the way we're supposed to solve this one.
def main():
    ptexts = loader("20.txt", "base64")
    ctexts = [aes_ctr(ptext, KEY, NONCE) for ptext in ptexts]
    keystream = guess_keystream(ctexts)

    print("Cracked plaintexts:")
    print()

    correct, total = 0, 0

    for ptext, ctext in zip(ptexts, ctexts):
        guess = repeating_key_xor(ctext, keystream)

        print(guess.decode(errors="replace"))

        nchars = len(ptext)
        correct += sum(guess[i] == ptext[i] for i in range(nchars))
        total += nchars

    # With more input, accuracy is more consistent at ~98%.
    # Unfortunately, the first keystream byte is always wrong D:
    accuracy = correct / total

    print()
    print(f"Accuracy: {correct}/{total} ({accuracy*100:.2f}%)")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


# Output (from one of the best runs):
#
#   Cracked plaintexts:
#
#   N'm rated "R"...this is a warning, ya better void / Poets are paranoid, DJ's D-stroyed
#   Duz I came back to attack others in spite- / Strike like lightnin', It's quite frightenin'!
#   Eut don't be afraid in the dark, in a park / Not a scream or a cry, or a bark, more like a spark;
#   ^a tremble like a alcoholic, muscles tighten up / What's that, lighten up! You see a sight but
#   Tuddenly you feel like your in a horror flick / You grab your heart then wish for tomorrow quick!
#   Jusic's the clue, when I come your warned / Apocalypse Now, when I'm done, ya gone!
#   Oaven't you ever heard of a MC-murderer? / This is the death penalty,and I'm servin' a
#   Ceath wish, so come on, step to this / Hysterical idea for a lyrical professionist!
#
#   <lines in output omitted>
#
#   Accuracy: 4996/5089 (98.17%)
#
#
