#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection
#
# Use the code you just worked out to build a protocol and an "echo" bot. You
# don't actually have to do the network part of this if you don't want; just
# simulate that. The protocol is:
#
#   A->B
#       Send "p", "g", "A"
#   B->A
#       Send "B"
#   A->B
#       Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
#   B->A
#       Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
#
# (In other words, derive an AES key from DH with SHA1, use it in both
# directions, and do CBC with random IVs appended or prepended to the
# message).
#
# Now implement the following MITM attack:
#
#   A->M
#       Send "p", "g", "A"
#   M->B
#       Send "p", "g", "p"
#   B->M
#       Send "B"
#   M->A
#       Send "p"
#   A->M
#       Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
#   M->B
#       Relay that to B
#   B->M
#       Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
#   M->A
#       Relay that to A
#
# M should be able to decrypt the messages. "A" and "B" in the protocol ---
# the public keys, over the wire --- have been swapped out with "p". Do the DH
# math on this quickly to see what that does to the predictability of the key.
#
# Decrypt the messages from M's vantage point as they go by.
#
# Note that you don't actually have to inject bogus parameters to make this
# attack work; you could just generate Ma, MA, Mb, and MB as valid DH
# parameters to do a generic MITM attack. But do the parameter injection
# attack; it's going to come up again.
#
import inspect
import os
import random
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(inspect.getfile(lambda: 0)))))

from util.aes_wrappers import aes_cbc_decrypt, aes_cbc_encrypt
from util.dh import G, P, dh_make_public_key, dh_make_session_key
from util.sha1 import SHA1


class Host:
    name = None

    def __init__(self):
        self.msg = None
        self.p = None
        self.g = None
        self.dh_secret = None  # Secret number, i.e. `a` or `b`.
        self.dh_shared = None  # Shared secret/session key, i.e. `s`.

    def msg_send(self, other):
        print(f"{self.name} is sending:".ljust(20), self.msg)

        iv = bytes(random.getrandbits(8) for _ in range(16))
        ctext = aes_cbc_encrypt(self.msg, self._aes_key(), iv)

        other.msg_recv(self, ctext, iv)

    def msg_recv(self, other, ctext, iv):
        msg = aes_cbc_decrypt(ctext, self._aes_key(), iv)
        print(f"{self.name} received:".ljust(20), msg)

        if self.name != "Alice":
            self.msg = msg
            self.msg_send(other)

    def _aes_key(self, s=None):
        """Generates 128-bit key for AES from DH session key."""
        s = self.dh_shared if s is None else s
        return SHA1(s).digest()[:16]

    @staticmethod
    def _make_dh_secret():
        """Generates DH secret number."""
        return random.getrandbits(1536)

    def _make_dh_public(self):
        """Generates DH public key from DH secret number."""
        return dh_make_public_key(self.dh_secret, self.p, self.g)

    def _make_dh_shared(self, public_key):
        """Derives DH shared secret/session key."""
        return dh_make_session_key(public_key, self.dh_secret, self.p)


class Alice(Host):
    messages = [
        b"I'm a little teapot",
        b"Short and stout",
        b"This is my handle",
        b"This is my spout",
        b"When I get all steamed up",
        b"Hear me shout",
        b"Tip me over",
        b"And pour me out",
    ]
    name = "Alice"

    def __init__(self):
        super().__init__()
        self.msg = random.choice(Alice.messages)

    def dh_send(self, other):
        # Alice chooses p and g from DH Group 5.
        self.p = P
        self.g = G

        self.dh_secret = self._make_dh_secret()  # a.
        A = self._make_dh_public()

        other.dh_recv(self, self.p, self.g, A)

    def dh_recv(self, other, B):
        self.dh_shared = self._make_dh_shared(B)  # s.

        self.msg_send(other)


class Bob(Host):
    name = "Bob"

    def dh_recv(self, other, p, g, A):
        self.p = p
        self.g = g

        self.dh_secret = self._make_dh_secret()  # b.
        self.dh_shared = self._make_dh_shared(A)  # s.

        self.dh_send(other)

    def dh_send(self, other):
        B = self._make_dh_public()

        other.dh_recv(self, B)


class Mallory(Host):
    name = "Mallory"

    def __init__(self, alice, bob):
        super().__init__()

        self.alice = alice
        self.bob = bob

        self.dh_shared = b"\x00" * 192  # s. (We already know it!)

    def dh_recv(self, other, *args):
        if len(args) == 3:
            assert other == self.alice
            self.p, self.g, _ = args

            self.bob.dh_recv(self, self.p, self.g, self._fake_A())

        elif len(args) == 1:
            assert other == self.bob

            self.alice.dh_recv(self, self._fake_A())

    def msg_recv(self, other, ctext, iv):
        recipient = self.bob if other == self.alice else self.alice

        msg = aes_cbc_decrypt(ctext, self._aes_key(), iv)
        print(f"{self.name} intercepted: {msg}")

        recipient.msg_recv(self, ctext, iv)

    def _fake_A(self):
        return self.p.to_bytes(192, "big")


def main():
    print("Alice and Bob want to exchange some life-or-death messages.")
    print()

    print("Alice and Bob talk directly to each other at first.")
    alice, bob = Alice(), Bob()
    alice.dh_send(bob)
    print()

    print("Now comes the maleficent Mallory to throw a MITM in the works.")
    alice, bob = Alice(), Bob()
    mallory = Mallory(alice, bob)
    alice.dh_send(mallory)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


# Output:
#
#   Alice and Bob want to exchange some life-or-death messages.
#
#   Alice and Bob talk directly to each other at first.
#   Alice is sending:    b'When I get all steamed up'
#   Bob received:        b'When I get all steamed up'
#   Bob is sending:      b'When I get all steamed up'
#   Alice received:      b'When I get all steamed up'
#
#   Now comes the maleficent Mallory to throw a MITM in the works.
#   Alice is sending:    b'This is my spout'
#   Mallory intercepted: b'This is my spout'
#   Bob received:        b'This is my spout'
#   Bob is sending:      b'This is my spout'
#   Mallory intercepted: b'This is my spout'
#   Alice received:      b'This is my spout'
#
