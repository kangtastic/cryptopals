#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Implement RSA
#
# There are two annoying things about implementing RSA. Both of them involve
# key generation; the actual encryption/decryption in RSA is trivial.
#
# First, you need to generate random primes. You can't just agree on a prime
# ahead of time, like you do in DH. You can write this algorithm yourself, but
# I just cheat and use OpenSSL's BN library to do the work.
#
# The second is that you need an "invmod" operation (the multiplicative
# inverse), which is not an operation that is wired into your language. The
# algorithm is just a couple lines, but I always lose an hour getting it to
# work.
#
# I recommend you not bother with primegen, but do take the time to get your
# own EGCD and invmod algorithm working.
#
# Now:
#
#   - Generate 2 random primes. We'll use small numbers to start, so you can
#     just pick them out of a prime table. Call them "p" and "q".
#   - Let n be p * q. Your RSA math is modulo n.
#   - Let et be (p-1)*(q-1) (the "totient"). You need this value only for
#     keygen.
#   - Let e be 3.
#   - Compute d = invmod(e, et). invmod(17, 3120) is 2753.
#   - Your public key is [e, n]. Your private key is [d, n].
#   - To encrypt: c = m**e%n. To decrypt: m = c**d%n
#   - Test this out with a number, like "42".
#   - Repeat with bignum primes (keep e=3).
#
# Finally, to encrypt a string, do something cheesy, like convert the string
# to hex and put "0x" on the front of it to turn it into a number. The math
# cares not how stupidly you feed it strings.
#
import inspect
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(inspect.getfile(lambda: 0)))))

from util.misc import get_prime, invmod
from util.rsa import make_rsa_keys, rsa
from util.text import print_indent

HAVE_CRYPTO = False
try:
    from Crypto.Util.number import isPrime
    HAVE_CRYPTO = True
except ImportError:
    pass

def _test_invmod():
    tests = [
        [42, 2017, 1969],
        [40, 1, 0],
        [52, -217, 96],
        [-486, 217, 121],
        [40, 2018, None],
    ]
    if all(invmod(a, b) == expected for a, b, expected in tests):
        return "Passed."
    return "Failed."


def _test_get_prime(bits=1024, rounds=10):
    for _ in range(rounds):
        prime = get_prime(bits)
        if prime.bit_length() != bits:
            return "Failed."
        if HAVE_CRYPTO and not isPrime(prime):
            return "Failed."

    if HAVE_CRYPTO:
        return "Passed."
    else:
        return "Probably passed; primality check skipped."


def _test_rsa():
    print()
    print("For the next test, we need some text to encrypt.")
    print()
    ptext = input("Enter some text: ").encode()
    print()

    print("Generating an RSA key pair, please wait.")
    pubkey, privkey = make_rsa_keys()

    print("Ciphertext encrypted with our private key:")
    ctext = rsa(ptext, privkey)
    print_indent(ctext)

    print("Plaintext decrypted with our public key:")
    new_ptext = rsa(ctext, pubkey)
    print_indent(new_ptext, as_hex=False)

    return "Passed." if ptext == new_ptext else "Failed."


def main():
    for test in _test_invmod, _test_get_prime, _test_rsa:
        func = test.__name__[6:]
        print(f"Testing our {func}():", test())


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


# Output:
#
#   Testing our invmod(): passed.
#   Testing our get_prime(): passed.
#
#   For the next test, we need some text to encrypt.
#
#   Enter some text: Buy me a pony!!
#
#   Generating an RSA key pair, please wait.
#   Ciphertext encrypted with our private key:
#
#       8d7e8b077f17c9dc39707f63ea5acddba3d7034a117c7eb909e116b6e16fe89d7b
#       d9b000fea92359136d532b38733e79ee855aa500e903997d109a2a7326cdc82c40
#       352982819606ae4e7925f4e7b9bb41f0bdc4da569c6f8ce810cacf33c6faaa9395
#       971cbc8ac78049d5e0193097a7087c1cd844123891177fd46811f29eb0
#
#   Plaintext decrypted with our public key:
#
#       Buy me a pony!!
#
#   Testing our rsa(): passed.
#
