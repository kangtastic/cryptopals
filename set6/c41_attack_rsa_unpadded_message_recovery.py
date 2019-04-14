#!/usr/bin/env python3
#
# Implement unpadded message recovery oracle
#
# Nate Lawson says we should stop calling it "RSA padding" and start calling
# it "RSA armoring". Here's why.
#
# Imagine a web application, again with the Javascript encryption, taking
# RSA-encrypted messages which (again: Javascript) aren't padded before
# encryption at all.
#
# You can submit an arbitrary RSA blob and the server will return plaintext.
# But you can't submit the same message twice: let's say the server keeps
# hashes of previous messages for some liveness interval, and that the
# message has an embedded timestamp:
#
#   {
#       time: 1356304276,
#       social: '555-55-5555',
#   }
#
# You'd like to capture other people's messages and use the server to decrypt
# them. But when you try, the server takes the hash of the ciphertext and uses
# it to reject the request. Any bit you flip in the ciphertext irrevocably
# scrambles the decryption.
#
# This turns out to be trivially breakable:
#
#   - Capture the ciphertext C
#
#   - Let N and E be the public modulus and exponent respectively
#
#   - Let S be a random number > 1 mod N. Doesn't matter what.
#
#   - Now:
#
#       C' = ((S**E mod N) C) mod N
#
#   - Submit C', which appears totally different from C, to the server,
#     recovering P', which appears totally different from P
#
#   - Now:
#
#             P'
#       P = -----  mod N
#             S
#
# Oops!
#
# Implement that attack.
#
# Careful about division in cyclic groups.
#
#   Remember: you don't simply divide mod N; you multiply by the
#   multiplicative inverse mod N. So you'll need a modinv() function.
#
import random
import sys
import time
from collections import deque
from hashlib import sha256
from socketserver import ThreadingTCPServer
from threading import Thread

sys.path.append("..")

from util.misc import invmod, modexp
from util.net import ClientMixIn, Handler
from util.rsa import make_rsa_keys, rsa
from util.text import from_bytes, to_bytes


class Steve(ThreadingTCPServer):
    timeout = 15

    def __init__(self, server_address):
        super().__init__(server_address, Handler)
        self.daemon_threads = True

        self.pubkey, self.privkey = make_rsa_keys()
        self.hashes = deque()

        self._handlers = {"pubkey": self.rsa_pubkey, "echo": self.rsa_echo}

    def rsa_pubkey(self):
        return self.pubkey

    def rsa_echo(self, ctext):
        # Clear records of old message hashes.
        now = int(time.time())
        while self.hashes and self.timeout < now - self.hashes[0][0]:
            self.hashes.popleft()

        cur_hash = sha256(ctext).digest()

        for _, old_hash in self.hashes:
            if old_hash == cur_hash:
                return None

        self.hashes.append((now, cur_hash))

        return rsa(ctext, self.privkey)


class Eve(ThreadingTCPServer, ClientMixIn):
    def __init__(self, server_address, target_address):
        super().__init__(server_address, Handler)
        self.daemon_threads = True

        self.remote_address = target_address
        self.remote_pubkey = None

        self._handlers = {"pubkey": self.rsa_pubkey, "echo": self.rsa_echo}

    def rsa_pubkey(self):
        self.remote_pubkey = self.parley("pubkey")
        return self.remote_pubkey

    def rsa_echo(self, ctext):
        # Eve is actually MITMing, not just eavesdropping.
        # To simulate an eavesdrop, have Eve discard the plaintext.
        self.parley("echo", ctext)

        # Steve will reject repeat submissions.
        assert self.parley("echo", ctext) is None

        # Eve cracks the ciphertext on her own.
        C = from_bytes(ctext)
        E, N = self.remote_pubkey
        S = random.randint(2, N - 1)

        C_ = (C * modexp(S, E, N)) % N
        ptext_ = self.parley("echo", to_bytes(C_))
        P_ = from_bytes(ptext_)

        P = (P_ * invmod(S, N)) % N
        ptext = to_bytes(P)

        print("Eve cracked Carol's plaintext:")
        print()
        print(" " * 4 + ptext.decode())
        print()

        # Carol won't notice a thing :P
        return ptext


class Carol(ClientMixIn):
    def __init__(self, remote_address, social):
        self.remote_address = remote_address
        self.remote_pubkey = None
        self.social = social

    def rsa_pubkey(self):
        self.remote_pubkey = self.parley("pubkey")

    def rsa_echo(self):
        now = int(time.time())

        ptext = str({"time": now, "social": self.social}).encode()
        ctext = rsa(ptext, self.remote_pubkey)

        reply = self.parley("echo", ctext)
        assert reply == ptext


def main():
    print("Steve and Carol are doing unpadded RSA, but Eve is listening in.")
    print()

    steve = Steve(("127.0.0.1", 0))
    Thread(target=steve.serve_forever).start()

    eve = Eve(("127.0.0.1", 0), steve.server_address)
    Thread(target=eve.serve_forever).start()

    carol = Carol(eve.server_address, "555-55-5555")
    carol.rsa_pubkey()
    carol.rsa_echo()

    for server in steve, eve:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


# Output:
#
#   Steve and Carol are doing unpadded RSA, but Eve is listening in.
#
#   Eve cracked Carol's plaintext:
#
#       {'time': 1554657304, 'social': '555-55-5555'}
#
