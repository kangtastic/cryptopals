#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright © 2019 James Seo <james@equiv.tech> (github.com/kangtastic).
# This file is released under the WTFPL, version 2 (wtfpl.net).
#
# mt19937.py: An implementation of the MT19337 PRNG in pure Python 3.
#
# Description: Zounds! Yet another rendition of pseudocode from Wikipedia!
#
# Usage: Why would anybody use this? Python's built-in PRNG, `random`, is
#        already a 32-bit MT19937 Mersenne Twister, and has more features.
#
#        DO NOT USE if you need something "performant" or "cryptographically
#        secure". :P
#
#        Anyway, in Python:
#
#           from .mt19937 import MT19937
#
#           # The seed defaults to the current UNIX time, but may
#           # optionally be specified during initialization.
#           rng = MT19337()
#           float_me_plz = rng.randf()    # e.g. 0.5597202227758069
#
#           rng2 = MT19337(12345)
#           int_me_instead = rng2.rand()  # 3992670690
#
#           # Existing instances may be reseeded.
#           rng.seed(12345)
#           int_me_again = rng.rand()     # 3992670690
#
# References:
#
#   Matsumoto, M., & Nishimura, T. (1998). Mersenne Twister: A
#       623-Dimensionally Equidistributed Uniform Pseudo-Random Number
#       Generator. ACM Transactions on Modeling and Computer Simulation, 8(1),
#       3-30.
#
#   https://en.wikipedia.org/wiki/Mersenne_Twister
#
#   http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/MT2002/CODES/mt19937ar.c
#


class MT19337:
    """An implementation of the MT19337 PRNG."""

    # Constants for MT19937 (original 32-bit variant).
    w, n, m, r = 32, 624, 397, 31
    u, s, t, l = 11, 7, 15, 18

    # Masks used by MT19337 (original 32-bit variant).
    a, b, c, d = 0x9908B0DF, 0x9D2C5680, 0xEFC60000, 0xFFFFFFFF
    f = 0x6C078965  # "Not part of the algorithm proper"
    width_mask = (1 << w) - 1  # 0xFFFFFFFF; same as d for 32-bit variant.
    lower_mask = (1 << r) - 1  # 0x7FFFFFFF
    upper_mask = lower_mask ^ width_mask  # 0x80000000

    def __init__(self, seed=None):
        """Initializer for the MT19337 PRNG."""
        self.MT = [0] * MT19337.n
        self.index = None
        self.seed(seed)

    def seed(self, seed):
        """Seed the generator with an int value :param:`seed`."""
        if not isinstance(seed, int):
            # Import is intentionally delayed.
            import time

            seed = int(time.time())

        self.index = MT19337.n
        self.MT[0] = MT19337.int32(seed)

        for i in range(1, MT19337.n):
            prev = self.MT[i - 1]
            self.MT[i] = MT19337.int32(
                (MT19337.f * (prev ^ (prev >> (MT19337.w - 2))) + i)
            )

    def rand(self):
        """:return: An `int` value on [0, (1 << w) - 1]."""
        # Outputs are tempered values based on self.MT[index]. _twist() is
        # called on the first invocation of rand(), and every n invocations
        # thereafter.
        if self.index == MT19337.n:
            self._twist()

        y = self.MT[self.index]
        self.index += 1
        return self.temper(y)

    def randf(self):
        """:return: A `float` value on [0, 1) with 53-bit resolution."""
        a, b = self.rand() >> 5, self.rand() >> 6
        return (a * 67108864 + b) / 9007199254740992  # py3 division :P

    def _twist(self):
        """Generate the next n values from the series x_i."""
        for i in range(MT19337.n):
            x = self.MT[i] & MT19337.upper_mask
            x |= self.MT[(i + 1) % MT19337.n] & MT19337.lower_mask
            x_a = x >> 1

            if x % 2:
                x_a ^= MT19337.a

            self.MT[i] = self.MT[(i + MT19337.m) % MT19337.n] ^ x_a

        self.index = 0

    @staticmethod
    def temper(y):
        """:return: A tempered value."""
        y ^= (y >> MT19337.u) & MT19337.d
        y ^= (y << MT19337.s) & MT19337.b
        y ^= (y << MT19337.t) & MT19337.c
        y ^= y >> MT19337.l
        return MT19337.int32(y)

    @staticmethod
    def int32(value):
        """:return: The lowest w bits of :param:`value`."""
        return value & MT19337.width_mask
