#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Implement Secure Remote Password (SRP)
#
# To understand SRP, look at how you generate an AES key from DH; now, just
# observe you can do the "opposite" operation an generate a numeric parameter
# from a hash. Then:
#
# Replace A and B with C and S (client & server)
#
#   C & S
#       Agree on N=[NIST Prime], g=2, k=3, I (email), P (password)
#   S
#       1. Generate salt as random integer
#       2. Generate string xH=SHA256(salt|password)
#       3. Convert xH to integer x somehow (put 0x on hexdigest)
#       4. Generate v=g**x % N
#       5. Save everything but x, xH
#   C->S
#       Send I, A=g**a % N (a la Diffie Hellman)
#   S->C
#       Send salt, B=kv + g**b % N
#   S, C
#       Compute string uH = SHA256(A|B), u = integer of uH
#   C
#       1. Generate string xH=SHA256(salt|password)
#       2. Convert xH to integer x somehow (put 0x on hexdigest)
#       3. Generate S = (B - k * g**x)**(a + u * x) % N
#       4. Generate K = SHA256(S)
#   S
#       1. Generate S = (A * v**u) ** b % N
#       2. Generate K = SHA256(S)
#   C->S
#       Send HMAC-SHA256(K, salt)
#   S->C
#       Send "OK" if HMAC-SHA256(K, salt) validates
#
# You're going to want to do this at a REPL of some sort; it may take a couple
# tries.
#
# It doesn't matter how you go from integer to string or string to integer
# (where things are going in or out of SHA256) as long as you do it
# consistently. I tested by using the ASCII decimal representation of integers
# as input to SHA256, and by converting the hexdigest to an integer when
# processing its output.
#
# This is basically Diffie Hellman with a tweak of mixing the password into
# the public keys. The server also takes an extra step to avoid storing an
# easily crackable password-equivalent.
#
import inspect
import os
import random
import sys
from hashlib import sha256
from socketserver import ThreadingTCPServer
from threading import Thread

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(inspect.getfile(lambda: 0)))))

from util.dh import P
from util.hmac import hmac_sha256
from util.misc import modexp
from util.net import ClientMixIn, Handler
from util.text import from_bytes, to_bytes


class Steve(ThreadingTCPServer):
    # P is the large prime from DH Group 5.
    n = P
    g = 2
    k = 3

    def __init__(self, server_address):
        super().__init__(server_address, Handler)
        self.daemon_threads = True
        self.accounts = {}
        self._handlers = {
            "hello": self.srp_hello,
            "kexch": self.srp_kexch,
            "authn": self.srp_authn,
        }

    def srp_hello(self, email, password):
        salt = random.getrandbits(32)

        x_bytes = sha256(to_bytes(salt) + password.encode()).digest()
        x = from_bytes(x_bytes)

        v = modexp(self.g, x, self.n)

        self.accounts[email] = {"password": password, "salt": salt, "v": v}

        return self.n, self.g, self.k

    def srp_kexch(self, email, A):
        account = self.accounts[email]

        b = random.getrandbits(1536)
        B = self.k * account["v"] + modexp(self.g, b, self.n)

        u_bytes = sha256(to_bytes(A, B)).digest()
        u = from_bytes(u_bytes)

        # We can't simply calculate the `A * v ** u` part of
        # `S = (A * v ** u) ** b % n`; the result is huge. But it seems
        # that all arithmetic is performed modulo n of late. *hint hint*
        S = modexp(A * modexp(account["v"], u, self.n), b, self.n)

        account["K"] = sha256(to_bytes(S)).digest()

        return account["salt"], B

    def srp_authn(self, email, input_hmac):
        account = self.accounts[email]
        hmac = hmac_sha256(account["K"], to_bytes(account["salt"]))

        return f"Login {'OK' if hmac == input_hmac else 'FAIL'}, {email}."


class Carol(ClientMixIn):
    def __init__(self, remote_address, email, password):
        self.n = None
        self.g = None
        self.k = None

        self.salt = None
        self.K = None

        self.remote_address = remote_address
        self.email = email
        self.password = password

    def srp_hello(self):
        self.n, self.g, self.k = self.parley("hello", self.email, self.password)

    def srp_kexch(self):
        a = random.getrandbits(1536)
        A = modexp(self.g, a, self.n)

        self.salt, B = self.parley("kexch", self.email, A)

        u_bytes = sha256(to_bytes(A, B)).digest()
        u = from_bytes(u_bytes)

        x_bytes = sha256(to_bytes(self.salt) + self.password.encode()).digest()
        x = from_bytes(x_bytes)

        S = modexp(B - self.k * modexp(self.g, x, self.n), a + u * x, self.n)

        self.K = sha256(to_bytes(S)).digest()

    def srp_authn(self):
        # Also send I (our email); Steve isn't storing state.
        hmac = hmac_sha256(self.K, self.salt.to_bytes(4, "big"))
        return self.parley("authn", self.email, hmac)


def main():
    print("Steve and Carol are doing SRP.")
    print()

    steve = Steve(("127.0.0.1", 0))
    Thread(target=steve.serve_forever).start()

    email, password = "foo@bar.com", "P@$$w0rd!~"

    carol = Carol(steve.server_address, email, password)

    print(f"Carol registers {email}.")
    carol.srp_hello()
    carol.srp_kexch()
    print(f"Carol is logging in:", carol.srp_authn())

    steve.shutdown()
    steve.server_close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


# Output:
#
#   Steve and Carol are doing SRP.
#
#   Carol registers foo@bar.com.
#   Carol is logging in: Login OK, foo@bar.com.
#
