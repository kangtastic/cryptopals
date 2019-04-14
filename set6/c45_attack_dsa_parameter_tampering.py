#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# DSA parameter tampering
#
# Take your DSA code from the previous exercise. Imagine it as part of an
# algorithm in which the client was allowed to propose domain parameters (the
# p and q moduli, and the g generator).
#
# This would be bad, because attackers could trick victims into accepting bad
# parameters. Vaudenay gave two examples of bad generator parameters:
# generators that were 0 mod p, and generators that were 1 mod p.
#
# Use the parameters from the previous exercise, but substitute 0 for "g".
# Generate a signature. You will notice something bad. Verify the signature.
# Now verify any other signature, for any other string.
#
# Now, try (p+1) as "g". With this "g", you can generate a magic signature
# s, r for any DSA public key that will validate against any string.
#
# For arbitrary z:
#
#   r = ((y**z) % p) % q
#
#         r
#   s =  --- % q
#         z
#
# Sign "Hello, world". And "Goodbye, world".
#
import random
import sys

sys.path.append("..")

from util.dsa import G, P, Q, make_dsa_keys
from util.misc import invmod, modexp
from util.sha1 import SHA1
from util.text import from_bytes


# No surprise, the security checks we removed would stop this attack.
def dsa_sign_insecure(bs, privkey, p=P, q=Q, g=G):
    x, z = privkey, from_bytes(SHA1(bs).digest())

    k, k_inv = None, None
    while k_inv is None:
        k = random.randrange(1, q)
        k_inv = invmod(k, q)

    r = modexp(g, k, p) % q
    s = (k_inv * (z + x * r)) % q

    return [r, s]


def dsa_verify_insecure(bs, sig, pubkey, p=P, q=Q, g=G):
    r, s = sig

    w, y, z = invmod(s, q), pubkey, from_bytes(SHA1(bs).digest())
    u1, u2 = (z * w) % q, (r * w) % q

    v = (modexp(g, u1, p) * modexp(y, u2, p) % p) % q

    return v == r


def _verify_msgs(msgs, sig, pubkey, g):
    for msg in msgs:
        if dsa_verify_insecure(msg, sig, pubkey, g=g):
            result = "VALID"
        else:
            result = "INVALID"

        print(f"    '{msg.decode()}':".ljust(44), result)


def attack_dsa_g0():
    msg = b"Twinkle, twinkle, little star"
    msgs = [
        b"Jack and Jill went up the hill",
        b"To fetch a pail of water",
        b"Jack fell down and broke his crown",
        b"And Jill came tumbling after",
    ]

    pubkey, privkey = make_dsa_keys(g=0)
    sig = dsa_sign_insecure(msg, privkey, g=0)

    print(f"Signed the message '{msg.decode()}'. (g == 0)")
    print("Does that message's signature validate others?")
    print()

    _verify_msgs(msgs, sig, pubkey, 0)


def attack_dsa_gp1():
    msgs = [b"Hello, world", b"Goodbye, world"]

    pubkey, privkey = make_dsa_keys(g=P + 1)  # Or g=1, g=2 * P + 1, etc.

    z = random.getrandbits(32)  # Arbitrary; it doesn't matter.
    r = modexp(pubkey, z, P) % Q
    s = (r * invmod(z, Q)) % Q

    sig = [r, s]

    print("Generated a magic signature. (g == p + 1)")
    print("Can we validate some messages with it?")
    print()

    _verify_msgs(msgs, sig, pubkey, 1)


def main():
    attack_dsa_g0()
    print()

    attack_dsa_gp1()
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass

# Output:
#
#   Signed the message 'Twinkle, twinkle, little star'. (g == 0)
#   Does that message's signature validate others?
#
#       'Jack and Jill went up the hill':        VALID
#       'To fetch a pail of water':              VALID
#       'Jack fell down and broke his crown':    VALID
#       'And Jill came tumbling after':          VALID
#
#   Generated a magic signature. (g == p + 1)
#   Can we validate some messages with it?
#
#       'Hello, world':                          VALID
#       'Goodbye, world':                        VALID
#
