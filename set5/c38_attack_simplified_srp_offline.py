#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Offline dictionary attack on simplified SRP
#
#   S
#       x = SHA256(salt|password)
#       v = g**x % n
#   C->S
#       I, A = g**a % n
#   S->C
#       salt, B = g**b % n, u = 128 bit random number
#   C
#       x = SHA256(salt|password)
#       S = B**(a + ux) % n
#       K = SHA256(S)
#   S
#       S = (A * v ** u)**b % n
#       K = SHA256(S)
#   C->S
#       Send HMAC-SHA256(K, salt)
#   S->C
#       Send "OK" if HMAC-SHA256(K, salt) validates
#
# Note that in this protocol, the server's "B" parameter doesn't depend on
# the password (it's just a Diffie Hellman public key).
#
# Make sure the protocol works given a valid password.
#
# Now, run the protocol as a MITM attacker: pose as the server and use
# arbitrary values for b, B, u, and salt.
#
# Crack the password from A's HMAC-SHA256(K, salt).
#
import random
import sys
from hashlib import sha256
from threading import Thread

sys.path.append("..")

from util.hmac import hmac_sha256
from util.misc import modexp
from util.text import from_bytes, to_bytes

from set5.c36_implement_srp import Carol, Steve


WORDS = ["foo", "bar", "baz", "qux", "quux", "corge", "grault", "garply"]


# Define Steven as an updated copy of Steve to fill the role of server.
class Steven(Steve):
    def srp_hello(self, email, password):
        salt = random.getrandbits(32)

        x_bytes = sha256(to_bytes(salt) + password.encode()).digest()
        x = from_bytes(x_bytes)

        # k is not used anymore.
        v = modexp(self.g, x, self.n)

        self.accounts[email] = {"password": password, "salt": salt, "v": v}

        # k is not used anymore.
        return self.n, self.g, None

    def srp_kexch(self, email, A):
        account = self.accounts[email]

        b = random.getrandbits(1536)
        B = modexp(self.g, b, self.n)

        # u is now simply a random uint128.
        u = random.getrandbits(128)

        S = modexp(A * modexp(account["v"], u, self.n), b, self.n)

        account["K"] = sha256(to_bytes(S)).digest()

        # Steven now sends u to Carl.
        return account["salt"], B, u


# Define Carl as an updated copy of Carol to fill the role of client.
class Carl(Carol):
    def srp_kexch(self):
        a = random.getrandbits(1536)
        A = modexp(self.g, a, self.n)

        # Carol now receives u from Steve.
        self.salt, B, u = self.parley("kexch", self.email, A)

        x_bytes = sha256(to_bytes(self.salt) + self.password.encode()).digest()
        x = from_bytes(x_bytes)

        # k is not used anymore.
        S = modexp(B, a + u * x, self.n)

        self.K = sha256(to_bytes(S)).digest()


# Define Carla as a copy of Carl to fill the role of client victim.
class Carla(Carl):
    pass


# Define Mallory as an attack-enabled copy of Steven to fill the role of
# fake server.
class Mallory(Steve):
    def srp_kexch(self, email, A):
        account = self.accounts[email]

        # Mallory doesn't know the password or anything about it.
        account.pop("password")
        account.pop("v")

        # "Use arbitrary values for b, B, u, and salt". The way Steven
        # generates these is already arbitrary; just do as Steven does.
        # (We could fix b, u, and salt to values that simplify the math,
        # but the attack doesn't seem to hinge upon doing this.)
        b = random.getrandbits(1536)
        B = modexp(self.g, b, self.n)

        u = random.getrandbits(128)

        # Mallory needs to save A, b, and u for her `authn` step.
        account.update({"A": A, "b": b, "u": u})

        # A salt was already generated in Steven's `hello` step.
        return account["salt"], B, u

    def srp_authn(self, email, input_hmac):
        account = self.accounts[email]

        salt = account["salt"]
        salt_bytes = to_bytes(salt)

        A, b, u = account["A"], account["b"], account["u"]

        for password in WORDS:
            # Find x as in Steven's `hello` step/Carla's `kexch` step.
            x_bytes = sha256(salt_bytes + password.encode()).digest()
            x = from_bytes(x_bytes)

            # Find v as in Steven's `hello` step.
            v = modexp(self.g, x, self.n)

            # Find S and K as in Steven's `kexch` step.
            S = modexp(A * modexp(v, u, self.n), b, self.n)
            K = sha256(to_bytes(S)).digest()

            if hmac_sha256(K, salt_bytes) == input_hmac:
                return f"{email}, your password is '{password}'. Muahahaha!"

        # Password wasn't found in the dictionary.
        return f"These are not the droids you're looking for."


def test_srp(server_cls, client_cls, email, password):
    server = server_cls(("127.0.0.1", 0))
    Thread(target=server.serve_forever).start()

    client = client_cls(server.server_address, email, password)
    client_name = client_cls.__name__

    print(f"    {client_name} registers {email}.")
    client.srp_hello()
    client.srp_kexch()
    print(f"    {client_name} is logging in:", client.srp_authn())

    server.shutdown()
    server.server_close()


def main():
    print("Steven and Carl are doing simplified SRP.")
    print()

    test_srp(Steven, Carl, "foo@bar.com", "P@$$w0rd!~")
    print()

    emails = ["baz@qux.com", "quux@corge.net", "grault@garply.org"]
    passwords = random.sample(WORDS, 2) + ["a password not in the dictionary"]

    print("Steven and Carla want to do the same.")
    print("Now comes the maleficent Mallory to throw a MITM in the works.")
    print()

    for email, password in zip(emails, passwords):
        test_srp(Mallory, Carla, email, password)
        print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


# Output:
#
#   Steven and Carl are doing simplified SRP.
#
#       Carol registers foo@bar.com.
#       Carol is logging in: Login OK, foo@bar.com.
#
#   Steven and Carla want to do the same.
#   Now comes the maleficent Mallory to throw a MITM in the works.
#
#       Carl registers baz@qux.com.
#       Carl is logging in: baz@qux.com, your password is 'corge'. Muahahaha!
#
#       Carl registers quux@corge.net.
#       Carl is logging in: quux@corge.net, your password is 'bar'. Muahahaha!
#
#       Carl registers grault@garply.org.
#       Carl is logging in: These are not the droids you're looking for.
#
