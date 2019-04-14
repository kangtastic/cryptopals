#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Break fixed-nonce CTR mode using substitutions
#
# Take your CTR encrypt/decrypt function and fix its nonce value to 0.
# Generate a random AES key.
#
# In *successive encryptions* (*not* in one big running CTR stream), encrypt
# each line of the base64 decodes of the following, producing multiple
# independent ciphertexts:
#
#   <note: see below>
#
# (This should produce 40 short CTR-encrypted ciphertexts).
#
# Because the CTR nonce wasn't randomized for each encryption, each ciphertext
# has been encrypted against the same keystream. This is very bad.
#
# Understanding that, like most stream ciphers (including RC4, and obviously
# any block cipher run in CTR mode), the actual "encryption" of a byte of data
# boils down to a single XOR operation, it should be plain that:
#
#   CIPHERTEXT-BYTE XOR PLAINTEXT-BYTE = KEYSTREAM-BYTE
#
# And since the keystream is the same for every ciphertext:
#
#   CIPHERTEXT-BYTE XOR KEYSTREAM-BYTE = PLAINTEXT-BYTE
#   (ie, "you don't say!")
#
# Attack this cryptosystem piecemeal: guess letters, use expected English
# language frequency to validate guesses, catch common English trigrams, and
# so on.
#
# Don't overthink it.
#
#   Points for automating this, but part of the reason I'm having you do this
#   is that I think this approach is suboptimal.
#
import base64
import sys
from functools import partial
from itertools import zip_longest

sys.path.append("..")

from util.aes import aes_ctr, make_aes_key
from util.text import single_byte_xor, repeating_key_xor

KEY = make_aes_key()
NONCE = 0
B64STRS = [
    "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
    "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
    "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
    "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
    "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
    "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
    "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
    "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
    "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
    "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
    "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
    "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
    "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
    "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
    "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
    "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
    "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
    "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
    "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
    "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
    "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
    "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
    "U2hlIHJvZGUgdG8gaGFycmllcnM/",
    "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
    "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
    "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
    "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
    "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
    "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
    "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
    "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
    "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
    "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
    "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
    "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
    "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
    "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
    "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
    "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
    "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
]


def guess_keystream(ctexts):
    keystream_byte = partial(single_byte_xor, key=True)

    transposed = zip_longest(*ctexts, fillvalue=-1)
    drop_nonexistent = (filter(lambda n: n != -1, chars) for chars in transposed)
    guessed_chars = map(keystream_byte, map(bytes, drop_nonexistent))
    return b"".join(guessed_chars)


def main():
    ptexts = [base64.b64decode(s) for s in B64STRS]
    ctexts = [aes_ctr(ptext, KEY, NONCE) for ptext in ptexts]
    keystream = guess_keystream(ctexts)

    print("CRACKED vs. ACTUAL".center(80).rstrip())
    print()

    correct, total = 0, 0

    for ptext, ctext in zip(ptexts, ctexts):
        guess = repeating_key_xor(ctext, keystream)

        print(f"{guess.decode(errors='replace')}".ljust(40) + f"{ptext.decode()}")

        nchars = len(ptext)
        correct += sum(guess[i] == ptext[i] for i in range(nchars))
        total += nchars

    accuracy = correct / total  # ~90-99%

    print()
    print(f"Accuracy: {correct}/{total} ({accuracy*100:.2f}%)")  # ~90-99%


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


# Output (from one of the best runs):
#
#                                  CRACKED vs. ACTUAL
#
#   I have met them at close of day         I have met them at close of day
#   Coming with vivid faces                 Coming with vivid faces
#   From counter or desk among grey         From counter or desk among grey
#   Eighteenth-century houses.              Eighteenth-century houses.
#   I have passed with a nod of the!he S    I have passed with a nod of the head
#   Or polite meaningless words,            Or polite meaningless words,
#   Or have lingered awhile and saie        Or have lingered awhile and said
#   Polite meaningless words,               Polite meaningless words,
#
#   <lines in output omitted>
#
#   Accuracy: 1105/1117 (98.93%)
#
