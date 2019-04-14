#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Implement Diffie-Hellman
#
# For one of the most important algorithms in cryptography this exercise
# couldn't be a whole lot easier.
#
# Set a variable "p" to 37 and "g" to 5. This algorithm is so easy I'm not
# even going to explain it. Just do what I do.
#
# Generate "a", a random number mod 37. Now generate "A", which is "g" raised
# to the "a" power mode 37 --- A = (g**a) % p.
#
# Do the same for "b" and "B".
#
# "A" and "B" are public keys. Generate a session key with them; set "s" to
# "B" raised to the "a" power mod 37 --- s = (B**a) % p.
#
# Do the same with A**b, check that you come up with the same "s".
#
# To turn "s" into a key, you can just hash it to create 128 bits of key
# material (or SHA256 it to create a key for encrypting and a key for a MAC).
#
# Ok, that was fun, now repeat the exercise with bignums like in the real
# world. Here are parameters NIST likes:
#
#   p:
#   ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
#   e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
#   3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
#   6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
#   24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
#   c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
#   bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
#   fffffffffffff
#
#   g: 2
#
# This is very easy to do in Python or Ruby or other high-level languages that
# auto-promote fixnums to bignums, but it isn't "hard" anywhere.
#
# Note that you'll need to write your own modexp (this is blackboard math,
# don't freak out), because you'll blow out your bignum library raising "a" to
# the 1024-bit-numberth power. You can find modexp routines on Rosetta Code
# for most languages.
#
import random
import sys
import textwrap

sys.path.append("..")

from util.dh import dh_make_public_key, dh_make_session_key


def main():
    print("Alice and Bob are doing Diffie-Hellman key exchange.")
    print()

    print("Generating two 1536-bit secret numbers a and b.")
    a, b = random.getrandbits(1536), random.getrandbits(1536)

    print("Generating two public keys A and B.")
    A, B = dh_make_public_key(a), dh_make_public_key(b)
    print()

    for name, pubkey in zip(["A", "B"], [A, B]):
        print(f"{name}:".ljust(8), end="")
        for i, line in enumerate(textwrap.wrap(pubkey.hex(), width=64)):
            print(" " * 8 + line if i else line.strip())
        print()

    print("Alice has B and Bob has A.")
    print("Will they independently derive the same session key?")
    print()

    for name, pubkey, secret in zip(["Alice", "Bob"], [B, A], [a, b]):
        sesskey = dh_make_session_key(pubkey, secret)
        print(f"{name} derived:".ljust(16), end="")
        for i, line in enumerate(textwrap.wrap(sesskey.hex(), width=56)):
            print(" " * 16 + line if i else line.strip())


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


# Output:
#
#   Alice and Bob are doing Diffie-Hellman key exchange.
#
#   Generating two 1536-bit secret numbers a and b.
#   Generating two public keys A and B.
#
#   A:      64ae4049c580e34a95bc5b0001d96b31928ba7644c1ed11d3a0422f62b89a8b6
#           f95801639a89bf3a043754e6aa9f981bd7a40fc53f40400dc3a47c57ec94face
#           8b4eb46f467ba98b3428237a8700ba6f05b1294f49fb99cf1d70be912cbb1d79
#           cb99ad80086e51f038f2bf1581f6bf3118da965d7702f4fe5a0cc4988f55ea04
#           e8428739d894791cd765c3bc7e1d9c5d73371344a951bc1f61e936652627e0c8
#           6b863d7d31e0b2d2d446279029f78b10d38ecf01da822aa4adcd0a26a98a4c06
#
#   B:      47d3c962d5ea976c4be0e91436f7676b63ca1d3d254b1ab16a1664d75a5fe76f
#           6672c88c4152f9fb631372e67612972b113e85bb29186949875e113b804352a7
#           365f960d3e830e0521a21d93372153b9bdb49dbc63bf2029065f9e338f8d2b3f
#           fedcc8561e9a5feccfa7a50a48d7271586fedb90f936ffd726a431d4182bbaab
#           60ac2a8b76cdede4b4e486e4a2dc94dfe4a9ecd2deca281bcb2cd652087ebcda
#           75d7e19809938ad165cae7dfb6a7c30c3580e5f25f1af33149c078b33656d9cc
#
#   Alice has B and Bob has A.
#   Will they independently derive the same session key?
#
#   Alice derived:  cdd9b1721411c6a19c74e294032f3463d86b70532b6d59fe0756fa1c
#                   70d9cc29ccc302e9ef195f430244c4a8477e76479528382d36061873
#                   99e5fa6055d9122d63e07bb5c847aca4d05bb638bf50e1aae7b3ca04
#                   049c242e15e109f26959bfe0377ec0f6660226f24feb8d4cddaba222
#                   8c702152f618ccda81e2d4070e4c0abe7c9bafbbff23db3c3fb4d405
#                   0ffa15a26d2ba7e8dce3c30a718dfa913766bc3eaa542ca1d1c1117f
#                   6e84e298118e648c693366bf4c79689ea12ac8010e5e2357
#   Bob derived:    cdd9b1721411c6a19c74e294032f3463d86b70532b6d59fe0756fa1c
#                   70d9cc29ccc302e9ef195f430244c4a8477e76479528382d36061873
#                   99e5fa6055d9122d63e07bb5c847aca4d05bb638bf50e1aae7b3ca04
#                   049c242e15e109f26959bfe0377ec0f6660226f24feb8d4cddaba222
#                   8c702152f618ccda81e2d4070e4c0abe7c9bafbbff23db3c3fb4d405
#                   0ffa15a26d2ba7e8dce3c30a718dfa913766bc3eaa542ca1d1c1117f
#                   6e84e298118e648c693366bf4c79689ea12ac8010e5e2357
#
