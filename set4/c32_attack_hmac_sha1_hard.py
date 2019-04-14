#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Break HMAC-SHA1 with a slightly less artificial timing leak.
#
# Reduce the sleep in your "insecure_compare" until your previous solution
# breaks. (Try 5ms to start.)
#
# Now break it again.
import inspect
import os
import sys
import time
from http.client import HTTPConnection

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(inspect.getfile(lambda: 0)))))

import set4.c31_attack_hmac_sha1_easy as easy

RETRIES = 10


def attack_hmac_sha1_hard(host, port):
    conn, guessed = HTTPConnection(host, port), ""

    for i in range(20):  # A SHA1 hash is 20 bytes long.
        guesses = []
        for _ in range(RETRIES):
            for n in range(256):
                signature = f"{guessed}{n:02x}".ljust(40, "0")

                now = time.time()

                conn.request("GET", f"/test?file=foo&signature={signature}")
                resp = conn.getresponse()

                delay = time.time() - now
                wrong_delay = ((i + 1) * easy.DELAY_MS) / 1000

                if resp.code == 200 or delay > wrong_delay:
                    guesses.append(n)
                    break

        if not guesses:
            print("~woopz~", end="", flush=True)
            break

        most_likely = f"{max(set(guesses), key=guesses.count):02x}"

        print(most_likely, end="", flush=True)
        guessed += most_likely

    return guessed


# Ticket: Attack is finicky re: timing and won't work on all systems.
# Disposition: ~closed, worksforme, wontfix~
def main(delay_ms=3):
    easy.DELAY_MS = delay_ms
    easy.attack_hmac_sha1 = attack_hmac_sha1_hard
    easy.main()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


# Output:
#
#   Breaking HMAC-SHA1 with an artificial timing leak.
#
#   Delay: 3ms
#
#   Steve started on http://127.0.0.1:9000/.
#
#   Actual:  ac4eb7f53736a5910a91011ca90bc3cfd4666a76
#   Guessed: ac4eb7f53736a5910a91011ca90bc3cfd4666a76
#
#   Success!
#
