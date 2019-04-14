#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Break a SHA-1 keyed MAC using length extension
#
# Secret-prefix SHA-1 MACs are trivially breakable.
#
# The attack on secret-prefix SHA1 relies on the fact that you can take the
# output of SHA-1 and use it as a new starting point for SHA-1, thus taking
# an arbitrary SHA-1 hash and "feeding it more data".
#
# Since the key precedes the data in secret-prefix, any additional data you
# feed the SHA-1 hash in this fashion will appear to have been hashed with
# the secret key.
#
# To carry out the attack, you'll need to account for the fact that SHA-1 is
# "padded" with the bit-length of the message; your forged message will need
# to include that padding. We call this "glue padding". The final message you
# actually forge will be:
#
#   SHA1(key || original-message || glue-padding || new-message)
#
# (where the final padding on the whole constructed message is implied).
#
# Note that to generate the glue padding, you'll need to know the original bit
# length of the message; the message itself is known to the attacker, but the
# secret key isn't, so you'll need to guess at it.
#
# This sounds more complicated than it is in practice.
#
# To implement the attack, first write the function that computes the MD
# padding of an arbitrary message and verify that you're generating the same
# padding that your SHA-1 implementation is using. This should take you 5-10
# minutes.
#
# Now, take the SHA-1 secret-prefix MAC of the message you want to forge ---
# this is just a SHA-1 hash --- and break it into 32 bit SHA-1 registers
# (SHA-1 calls them "a", "b", "c", &c).
#
# Modify your SHA-1 implementation so that callers can pass in new values for
# "a", "b", "c" &c (they normally start at magic numbers). With the registers
# "fixated", hash the additional data you want to forge.
#
# Using this attack, generate a secret-prefix MAC under a secret key (choose a
# random word from /usr/share/dict/words or something) of the string:
#
#   "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
#
# Forge a variant of this message that ends with ";admin=true".
#
# This is a very useful attack.
#
#   For instance: Thai Duong and Juliano Rizzo, who got to this attack before
#   we did, used it to break the Flickr API.
#
import inspect
import os
import random
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(inspect.getfile(lambda: 0)))))

from set4.c28_implement_sha1_keyed_mac import check_sha1_pmac, make_sha1_pmac
from util.sha1 import SHA1

WORDS = [b"Aeaea", b"Aiea", b"Aia", b"Io", b"Eaio", b"Oea", b"ai", b"Aa"]


def sha1_padding(msg, klen=0):
    ml_bytes = len(msg) + klen
    ml = ml_bytes * 8

    # Pre-processing: Total length is a multiple of 512 bits.
    padding = b"\x80"
    padding += b"\x00" * (-(ml_bytes + 9) % 64)
    padding += ml.to_bytes(8, "big")

    return padding


def main():
    orig_msg = (
        b"comment1=cooking%20MCs;userdata=foo;"
        b"comment2=%20like%20a%20pound%20of%20bacon"
    )
    key = random.choice(WORDS)
    pmac = make_sha1_pmac(orig_msg, key)

    print("First, let's verify that a message authenticates.")
    print()
    print("Message:      ", orig_msg)
    print("Key:          ", "<secret>")
    print("MAC:          ", pmac)
    print("Authenticates:", check_sha1_pmac(orig_msg, key, pmac))
    print()
    print()
    print("Now for the attack.")

    extra_data = b";admin=true"

    crafted_pmac = SHA1()  # Our result object.
    crafted_msg, h, key_length = b"", pmac.h.copy(), None

    # Since we don't know the key's bit length, we have to guess at it.
    for klen in range(1, 256):
        # Set "initial" state from original hash.
        crafted_pmac.h = h

        # The bit length of the key affects all of these.
        glue_padding = sha1_padding(orig_msg, klen)
        crafted_msg = orig_msg + glue_padding + extra_data
        padded = extra_data + sha1_padding(crafted_msg, klen)

        # Calculate hash of this particular crafted message.
        chunks = (padded[i : i + 64] for i in range(0, len(padded), 64))
        crafted_pmac._process(chunks)

        if check_sha1_pmac(crafted_msg, key, crafted_pmac):
            key_length = klen
            break
    else:
        print("Unfortunately, we failed.")
        return

    print()
    print("Message:      ", crafted_msg)
    print("Key:          ", "<still secret>")
    print("Key length:   ", key_length)  # We guessed this.
    print("MAC:          ", crafted_pmac)
    print("Authenticates:", check_sha1_pmac(crafted_msg, key, crafted_pmac))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


# Output:
#
#   First, let's verify that a message authenticates.
#
#   Message:       b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
#   Key:           <secret>
#   MAC:           17e43076d61a6b3e4604ec257be3ee8e46e10d5b
#   Authenticates: True
#
#
#   Now for the attack.
#
#   Message:       b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x88;admin=true'
#   Key:           <still secret>
#   Key length:    4
#   MAC:           18cc865b152a6d9d98b5a680c5a8d73d4e281124
#   Authenticates: True
#
