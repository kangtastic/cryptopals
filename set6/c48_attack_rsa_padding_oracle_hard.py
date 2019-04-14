#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)
#
# Cryptanalytic MVP award
#   This is an extraordinarily useful attack. PKCS#1v15 padding, despite being
#   totally insecure, is the default padding used by RSA implementations. The
#   OAEP standard that replaces it is not widely implemented. This attack
#   routinely breaks SSL/TLS.
#
# This is a continuation of challenge #47; it implements the complete BB'98
# attack.
#
# Set yourself up the way you did in #47, but this time generate a 768 bit
# modulus.
#
# To make the attack work with a realistic RSA keypair, you need to reproduce
# step 2b from the paper, and your implementation of Step 3 needs to handle
# multiple ranges.
#
# The full Bleichenbacher attack works basically like this:
#
#   - Starting from the smallest 's' that could possibly produce a plaintext
#     bigger than 2B, iteratively search for an 's' that produces a conformant
#     plaintext.
#   - For our known 's1' and 'n', solve m1=m0s1-rn (again: just a definition
#     of modular multiplication) for 'r', the number of times we've wrapped
#     the modulus.
#   - 'm0' and 'm1' are unknowns, but we know both are conformant PKCS#1v1.5
#     plaintexts, and so are between [2B,3B].
#   - We substitute the known bounds for both, leaving only 'r' free, and
#     solve for a range of possible 'r' values. This range should be small!
#   - Solve m1=m0s1-rn again but this time for 'm0', plugging in each value of
#     'r' we generated in the last step. This gives us new intervals to work
#     with. Rule out any interval that is outside 2B,3B.
#   - Repeat the process for successively higher values of 's'. Eventually,
#     this process will get us down to just one interval, whereupon we're back
#     to exercise #47.
#
# What happens when we get down to one interval is, we stop blindly
# incrementing 's'; instead, we start rapidly growing 'r' and backing it out
# to 's' values by solving m1=m0s1-rn for 's' instead of 'r' or 'm0'. So much
# algebra! Make your teenage son do it for you! *Note: does not work well in
# practice*
#
import random
import signal
import sys
from datetime import datetime
from multiprocessing import Pool

sys.path.append("..")

from util.misc import cpu_threads, invmod, modexp
from util.rsa import make_rsa_keys, rsa
from util.text import byte_length, pad_pkcs15, unpad_pkcs15

CPUS = cpu_threads()
KEY_LENGTHS = [512, 768, 1024, 1536, 2048, 3072, 4096]
PTEXTS = [
    b"Sing a song of sixpence a pocket full of rye",
    b"Four and twenty blackbirds baked in a pie",
    b"When the pie was opened the birds began to sing",
    b"Oh wasn't that a dainty dish to set before the king?",
    b"The king was in his counting house counting out his money",
    b"The queen was in the parlour eating bread and honey",
    b"The maid was in the garden hanging out the clothes",
    b"When down came a blackbird and pecked off her nose",
]


# Alas, the oracle returned by make_oracle() in the previous challenge
# can't be pickled by multiprocessing. We must pass the private key to
# the oracle. At least we won't be using it for outright decryption.
def oracle(ctext, privkey):
    bsize = byte_length(privkey[1])
    ptext = rsa(ctext, privkey)
    return ptext.rjust(bsize, b"\x00")[:2] == b"\x00\x02"


def mp_test_s(mp_data):
    c_0, s, e, n, privkey = mp_data
    if oracle((c_0 * modexp(s, e, n)) % n, privkey):
        return s


class PKCS15Cracker:
    def __init__(self, pubkey, privkey, ctext):
        orig_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
        self.pool = Pool(CPUS)
        signal.signal(signal.SIGINT, orig_handler)

        self.e, self.n = pubkey
        self.privkey = privkey

        # Save the modulus length for the progress indicator.
        self.bits = self.n.bit_length()

        # Find s_0 and save initial state.
        self.c_0 = ctext
        self.s_0 = self.s = self.mp_find_s(self.gen_incr(1))

        self.c_0 = (self.c_0 * modexp(self.s, self.e, self.n)) % self.n
        self.i = 0
        self.B = 1 << (byte_length(self.n) - 2) * 8
        self.M = {(self.B * 2, self.B * 3 - 1)}

        self.result = None

    @property
    def _M(self):
        return list(self.M)[0]

    def show_progress(self, width=48, char="\u2588"):
        # This isn't perfect, as the number of iterations required to crack
        # the ciphertext isn't the same as the number of bits in the modulus,
        # varying in testing from ~90-98%. Having the bar jump to 100% is OK.
        iters = min(self.i, self.bits) if self.result is None else self.bits
        pct = iters * 100 // self.bits
        bar = (char * (iters * width // self.bits)).ljust(width)
        print(f"\r[{bar}] {pct}%", end="", flush=True)

    def decrypt(self):
        while self.result is None:
            self.iterate()

        self.show_progress()
        print()

        return self.result

    def iterate(self):
        self.i += 1
        self.show_progress()

        self.s = self.find_s()
        self.M = self.find_ranges()

        if len(self.M) == 1:
            a, b = self._M
            if a == b:
                self.result = (a * invmod(self.s_0, self.n)) % self.n
        elif len(self.M) > 1:
            print(f"(M_{self.i} has {len(self.M)} ranges, mumble mumble~)")

    def find_s(self):
        if self.i == 1:
            s_gen = self.gen_incr((self.n + self.B * 3 - 1) // (self.B * 3))
        elif self.i > 1 and len(self.M) > 1:
            s_gen = self.gen_incr(self.s + 1)
        else:
            s_gen = self.gen_from_state()

        return self.mp_find_s(s_gen)

    def find_ranges(self):
        M = set()

        for a, b in self.M:
            # lower = ceil((a*s_i-3B+1))/n). As we fake ceiling
            # division, the 1's in 3B+1 and n-1 cancel out.
            lower = (self.s * a - self.B * 3 + self.n) // self.n
            upper = (self.s * b - self.B * 2) // self.n

            for r in range(lower, upper + 1):
                # a_, b_ = ceil((2B+rn)/s_i), floor((3B-1+rn)/s_i)
                a_ = (self.n * r + self.B * 2 + self.s - 1) // self.s
                b_ = (self.n * r + self.B * 3 - 1) // self.s

                M.add((max(a, a_), min(b, b_)))

        return M

    def mp_find_s(self, s_gen):
        while True:
            mp_data = (
                (self.c_0, next(s_gen), self.e, self.n, self.privkey)
                for _ in range(CPUS)
            )
            for candidate in self.pool.imap(mp_test_s, mp_data):
                if candidate:
                    return candidate

    @staticmethod
    def gen_incr(s):
        while True:
            yield s
            s += 1

    def gen_from_state(self):
        a, b = self._M
        r = ((self.s * b - self.B * 2) * 2 + self.n - 1) // self.n
        while True:
            lower = (self.B * 2 + self.n * r + b - 1) // b
            upper = (self.B * 3 + self.n * r + a - 1) // a
            yield from range(lower, upper)
            r += 1

    def shutdown(self):
        self.pool.close()


def main():
    print(f"Enter a key length in {KEY_LENGTHS}.")
    print("Default is 768. Longer lengths ~dramatically~ extend runtime.")
    print()

    key_length, ans = None, input("> ")
    try:
        key_length = int(ans)
    except ValueError:
        pass
    if key_length not in KEY_LENGTHS:
        key_length = 768
    print()

    ptext, bsize = random.choice(PTEXTS), key_length // 8
    while len(ptext) > bsize - 11:
        ptext = random.choice(PTEXTS)
    print(f"Original plaintext: '{ptext.decode()}'")
    print()

    print(f"Generating an RSA-{key_length} key pair.")
    pubkey, privkey = make_rsa_keys(key_length)

    print("Padding and encrypting plaintext using PKCS#1 1.5.")
    padded = pad_pkcs15(ptext, bsize)
    ctext = rsa(padded, pubkey, as_bytes=False)
    print()

    print(f"Cracking ciphertext using {CPUS} cores, please wait.")
    now = datetime.now()
    cracker = PKCS15Cracker(pubkey, privkey, ctext)
    padded = cracker.decrypt()
    cracker.shutdown()
    print(f"Finished in {datetime.now() - now}.")
    print()

    cracked_ptext = unpad_pkcs15(padded, bsize)
    print(f"Cracked plaintext:  '{cracked_ptext.decode()}'")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass

# Output:
#
#   Enter a key length in [512, 768, 1024, 1536, 2048, 3072, 4096].
#   Default is 768. Longer lengths ~dramatically~ extend runtime.
#
#   > 4096
#
#   Original plaintext: 'The maid was in the garden hanging out the clothes'
#
#   Generating an RSA-4096 key pair.
#   Padding and encrypting plaintext using PKCS#1 1.5.
#   Cracking ciphertext using 11 cores, please wait.
#   (M_1 has 3 ranges, mumble mumble~)
#   Finished in 0:37:18.434245.
#
#   Cracked plaintext:  'The maid was in the garden hanging out the clothes'
#
