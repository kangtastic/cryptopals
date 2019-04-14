#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Implement DH with negotiated groups, and break with malicious "g" parameters
#
#   A->B
#       Send "p", "g"
#   B->A
#       Send ACK
#   A->B
#       Send "A"
#   B->A
#       Send "B"
#   A->B
#       Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
#   B->A
#       Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
#
# Do the MITM attack again, but play with "g". What happens with:
#
#   g = 1
#   g = p
#   g = p - 1
#
# Write attacks for each.
#
# When does this ever happen?
#
#   Honestly, not that often in real-world systems. If you can mess with "g",
#   chances are you can mess with something worse. Most systems pre-agree on
#   a static DH group. But the same construction exists in Elliptic Curve
#   Diffie-Hellman, and this becomes more relevant there.
#
import inspect
import os
import random
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(inspect.getfile(lambda: 0)))))

from set5.c34_attack_dh_mitm_parameter_injection import Host
from util.aes import aes_cbc_decrypt
from util.dh import P
from util.text import englishness


# Redefine Alice, Bob, and Mallory; monkeypatching would be hard(er) to follow.
class Alice(Host):
    name = "Alice"

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

    def __init__(self):
        super().__init__()
        self.msg = random.choice(Alice.messages)

    def dh_send_group(self, other, g):
        # Alice chooses p from DH Group 5, but the g she chooses
        # is one of 1, p, or p - 1. She then sends p and g to "Bob".
        self.p = P
        self.g = g

        other.dh_recv_group(self, self.p, self.g)

    def dh_recv_ack(self, other, ack):
        # Alice checks that she received "ACK" from "Bob".
        # If so, she generates a and A, then sends A to "Bob".
        if ack == "ACK":
            self.dh_secret = self._make_dh_secret()  # a.
            A = self._make_dh_public()

            self.dh_send_A(other, A)

    def dh_send_A(self, other, A):
        other.dh_recv_A(self, A)

    def dh_recv_B(self, other, B):
        # Alice derives s from the B she received from "Bob",
        # then uses it to send "Bob" an encrypted message.
        self.dh_shared = self._make_dh_shared(B)  # s.

        self.msg_send(other)


class Bob(Host):
    name = "Bob"

    def dh_recv_group(self, other, p, g):
        # Bob blindly accepts p and g from "Alice", then replies with "ACK".
        self.p = p
        self.g = g

        self.dh_send_ack(other, "ACK")

    def dh_send_ack(self, other, ack):
        other.dh_recv_ack(self, ack)

    def dh_recv_A(self, other, A):
        # Bob accepts A from "Alice". He generates b and B,
        # uses b and A to derive s, then replies with B.
        self.dh_secret = self._make_dh_secret()  # b.

        self.dh_shared = self._make_dh_shared(A)  # s.

        B = self._make_dh_public()

        self.dh_send_B(other, B)

    def dh_send_B(self, other, B):
        other.dh_recv_B(self, B)


class Mallory(Host):
    name = "Mallory"

    def __init__(self, alice, bob):
        super().__init__()

        self.alice = alice
        self.bob = bob

    # For the most part, Mallory just relays all messages during DH.
    def dh_recv_group(self, other, p, g):
        assert other == self.alice

        # If g ∈ {1, P - 1, P}, we can predict s.
        if g == 1:
            self.dh_shared = g.to_bytes(192, "big")
        elif g == P:
            self.dh_shared = int.to_bytes(0, 192, "big")
        elif g == P - 1:
            # s may be 1 % p or -1 % p, i.e. 1 or p - 1.
            # We can't tell yet; keep `self.dh_shared` as None.
            pass
        else:
            raise ValueError("g is not 1, p, or p - 1")

        self.dh_relay_group(p, g)

    def dh_relay_group(self, p, g):
        self.bob.dh_recv_group(self, p, g)

    def dh_recv_ack(self, other, ack):
        assert other == self.bob
        self.dh_relay_ack(ack)

    def dh_relay_ack(self, ack):
        self.alice.dh_recv_ack(self, ack)

    def dh_recv_A(self, other, A):
        assert other == self.alice
        self.dh_relay_A(A)

    def dh_relay_A(self, A):
        self.bob.dh_recv_A(self, A)

    def dh_recv_B(self, other, B):
        assert other == self.bob
        self.dh_relay_B(B)

    def dh_relay_B(self, B):
        self.alice.dh_recv_B(self, B)

    def msg_recv(self, other, ctext, iv):
        recipient = self.bob if other == self.alice else self.alice

        # If g == p - 1, try decrypting from both possible values of s.
        if self.dh_shared is None:
            ss = (s.to_bytes(192, "big") for s in (1, P - 1))
            msgs = {s: aes_cbc_decrypt(ctext, self._aes_key(s), iv) for s in ss}

            # Keep the s yielding the more English-like plaintext.
            self.dh_shared = max(msgs, key=lambda k: englishness(msgs[k]))
            msg = msgs[self.dh_shared]  # Keep that plaintext too.
        else:
            msg = aes_cbc_decrypt(ctext, self._aes_key(), iv)

        print(f"{self.name} intercepted: {msg}")

        recipient.msg_recv(self, ctext, iv)


def main():
    print("Alice and Bob want to exchange some life-or-death messages.")
    print("But the maleficent MITMer Mallory waits in the wings!")
    print()

    for g, txt in zip([1, P, P - 1], ["1", "p", "p - 1"]):
        print(f"Alice makes the error of negotiating g == {txt} during DH.")
        alice, bob = Alice(), Bob()
        mallory = Mallory(alice, bob)
        alice.dh_send_group(mallory, g)
        print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


# Output:
#
#   Alice and Bob want to exchange some life-or-death messages.
#   But the maleficent MITMer Mallory waits in the wings!
#
#   Alice makes the error of negotiating g == 1 during DH.
#   Alice is sending:    b"I'm a little teapot"
#   Mallory intercepted: b"I'm a little teapot"
#   Bob received:        b"I'm a little teapot"
#   Bob is sending:      b"I'm a little teapot"
#   Mallory intercepted: b"I'm a little teapot"
#   Alice received:      b"I'm a little teapot"
#
#   Alice makes the error of negotiating g == p during DH.
#   Alice is sending:    b'And pour me out'
#   Mallory intercepted: b'And pour me out'
#   Bob received:        b'And pour me out'
#   Bob is sending:      b'And pour me out'
#   Mallory intercepted: b'And pour me out'
#   Alice received:      b'And pour me out'
#
#   Alice makes the error of negotiating g == p - 1 during DH.
#   Alice is sending:    b'When I get all steamed up'
#   Mallory intercepted: b'When I get all steamed up'
#   Bob received:        b'When I get all steamed up'
#   Bob is sending:      b'When I get all steamed up'
#   Mallory intercepted: b'When I get all steamed up'
#   Alice received:      b'When I get all steamed up'
#
