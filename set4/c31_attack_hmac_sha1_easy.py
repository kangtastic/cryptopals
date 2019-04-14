#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Implement and break HMAC-SHA1 with an artificial timing leak
#
# The psuedocode on Wikipedia should be enough. HMAC is very easy.
#
# Using the web framework of your choosing (Sinatra, web.py, whatever), write
# a tiny application that has a URL that takes a "file" argument and a
# "signature" argument, like so:
#
#   http://localhost:9000/test?file=foo&signature=46b4ec586117154dacd49d664e5d63fdc88efb51
#
# Have the server generate an HMAC key, and then verify that the "signature"
# on incoming requests is valid for "file", using the "==" operator to
# compare the valid MAC for a file with the "signature" parameter (in other
# words, verify the HMAC the way any normal programmer would verify it).
#
# Write a function, call it "insecure_compare", that implements the ==
# operation by doing byte-at-a-time comparisons with early exit (ie, return
# false at the first non-matching byte).
#
# In the loop for "insecure_compare", add a 50ms sleep (sleep 50ms after each
# byte).
#
# Use your "insecure_compare" function to verify the HMACs on incoming
# requests, and test that the whole contraption works. Return a 500 if the MAC
# is invalid, and a 200 if it's OK.
#
# Using the timing leak in this application, write a program that discovers
# the valid MAC for any file.
#
# Why artificial delays?
#
#   Early-exit string compares are probably the most common source of
#   cryptographic timing leaks, but they aren't especially easy to exploit.
#   In fact, many timing leaks (for instance, any in C, C++, Ruby, or Python)
#   probably aren't exploitable over a wide-area network at all. To play with
#   attacking real-world timing leaks, you have to start writing low-level
#   timing code. We're keeping things cryptographic in these challenges.
#
import inspect
import os
import random
import sys
import time
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
from itertools import zip_longest
from socketserver import ThreadingMixIn
from threading import Thread

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(inspect.getfile(lambda: 0)))))

from util.hmac import hmac_sha1

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9000
HMAC_KEY = bytes(random.getrandbits(8) for _ in range(64))
DELAY_MS = 50


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("test?")
        assert len(path) == 2

        params = {k: v for k, v in (kv.split("=") for kv in path[1].split("&"))}
        file, signature = params["file"], bytes.fromhex(params["signature"])

        if insecure_compare(signature, hmac_sha1(HMAC_KEY, file)):
            self._respond(200, b"Signature valid")
        else:
            self._respond(500, b"Signature invalid")

    # Suppress logging all incoming requests to stderr.
    def log_message(self, fmt, *args):
        return

    def _respond(self, code, response):
        self.send_response(code)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(response)


# Backport of Python 3.7's ThreadingHTTPServer, in case we're not on 3.7.
class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


def start_server(host, port):
    server = ThreadingHTTPServer((host, port), Handler)
    Thread(target=server.serve_forever).start()

    return server, host, port


def insecure_compare(bs1, bs2):
    # Total delay in seconds is <# matching bytes> * DELAY_MS / 1000.
    for b1, b2 in zip_longest(bs1, bs2, fillvalue=-1):
        if b1 != b2:
            return False
        time.sleep(DELAY_MS / 1000)
    return True


def attack_hmac_sha1(host, port):
    conn, guessed = HTTPConnection(host, port), ""

    for i in range(20):  # A SHA1 hash is 20 bytes long.
        for n in range(256):
            signature = f"{guessed}{n:02x}".ljust(40, "0")

            now = time.time()

            conn.request("GET", f"/test?file=foo&signature={signature}")
            resp = conn.getresponse()

            delay = time.time() - now
            wrong_delay = ((i + 1) * DELAY_MS) / 1000

            if resp.code == 200 or delay > wrong_delay:
                print(f"{n:02x}", end="", flush=True)
                guessed += f"{n:02x}"
                break

        if i + 1 != len(guessed) // 2:
            print("~woopz~", end="", flush=True)
            break

    return guessed


def main():
    print("Breaking HMAC-SHA1 with an artificial timing leak.")
    print()
    print(f"Delay: {DELAY_MS}ms")
    print()

    server, host, port = start_server(SERVER_HOST, SERVER_PORT)
    print(f"Server started on http://{host}:{port}/.")
    print()

    goal = hmac_sha1(HMAC_KEY, "foo")
    goal = "".join(f"{value:02x}" for value in goal)
    print("Actual: ", goal)
    print("Guessed:", end=" ", flush=True)

    guessed = attack_hmac_sha1(host, port)
    print()
    print()
    print("Success!" if goal == guessed else "FAILED!")

    server.shutdown()
    server.server_close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


# Output:
#
#   Breaking HMAC-SHA1 with an artificial timing leak.
#
#   Delay: 50ms
#
#   Steve started on http://127.0.0.1:9000/.
#
#   Actual:  dd424a994e6e91f39a2466b82b8d4bdbf8629c2e
#   Guessed: dd424a994e6e91f39a2466b82b8d4bdbf8629c2e
#
#   Success!
#
