#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Break SRP with a zero key
#
# Get your SRP working in an actual client-server setting. "Log in" with a
# valid password using the protocol.
#
# Now log in without your password by having the client send 0 as its "A"
# value. What does this to the "S" value that both sides compute?
#
# Now log in without your password by having the client send N, N*2, &c.
#
# Cryptanalytic MVP award
#
#   Trevor Perrin and Nate Lawson taught us this attack 7 years ago. It is
#   excellent. Attacks on DH are tricky to "operationalize". But this attack
#   uses the same concepts, and results in auth bypass. Almost every
#   implementation of SRP we've ever seen has this flaw; if you see a new one,
#   go look for this bug.
#
import sys
from hashlib import sha256
from threading import Thread

sys.path.append("..")

from set5.c36_implement_srp import Carol, Steve


# Define Charlie as an attack-enabled copy of Carol.
class Charlie(Carol):
    def srp_kexch(self, i=0):
        # If Charlie sends A such that A % N == 0, Steve calculates S to be 0,
        # i.e. all integer multiples of N, including 0, result in S being 0.

        # We still need the salt later, so save it from Steve's reply.
        self.salt, _ = self.parley("kexch", self.email, i * self.n)

        # Charlie obtains K in the same way Steve does.
        # In our case, when S is 0, Steve hashes nothing and calls it K.
        self.K = sha256().digest()


def main():
    print("Steve and Charlie are doing SRP.")
    print("Steve trusts Charlie, but Charlie is zeroing the key!")
    print()

    accounts = [
        ["foo@bar.com", "P@$$w0rd!~"],
        ["firstname@lastname.net", "qazwsxedc"],
        ["another@email.org", "BEES"],
    ]

    for i, account in enumerate(accounts):
        email, password = account

        steve = Steve(("127.0.0.1", 0))
        Thread(target=steve.serve_forever).start()

        print(f"Charlie registers {email}.")
        charlie = Charlie(steve.server_address, email, password)
        charlie.srp_hello()

        print(f"Charlie is sending {i} * n as A.")
        charlie.srp_kexch(i)

        print(f"Charlie is logging in:", charlie.srp_authn())
        print()

        steve.shutdown()
        steve.server_close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


# Output:
#
#   Steve and Charlie are doing SRP.
#   Steve trusts Charlie, but Charlie is zeroing the key!
#
#   Charlie registers foo@bar.com.
#   Charlie is sending 0 * n as A.
#   Charlie is logging in: Login OK, foo@bar.com.
#
#   Charlie registers firstname@lastname.net.
#   Charlie is sending 1 * n as A.
#   Charlie is logging in: Login OK, firstname@lastname.net.
#
#   Charlie registers another@email.org.
#   Charlie is sending 2 * n as A.
#   Charlie is logging in: Login OK, another@email.org.
#
