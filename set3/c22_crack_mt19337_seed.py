#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Crack an MT19937 seed
#
# Make sure your MT19937 accepts an integer seed value. Test it (verify that
# you're getting the same sequence of outputs given a seed).
#
# Write a routine that performs the following operation:
#
# - Wait a random number of seconds between, I don't know, 40 and 1000.
# - Seeds the RNG with the current Unix timestamp
# - Waits a random number of seconds again.
# - Returns the first 32 bit output of the RNG.
#
# You get the idea. Go get coffee while it runs. Or just simulate the passage
# of time, although you're missing some of the fun of this exercise if you do
# that.
#
# From the 32 bit RNG output, discover the seed.
#
import random
import sys
import time

sys.path.append("..")

from util.mt19937 import MT19337


def wait_progress(secs, width=48, char=u"\u2588"):
    for t in range(1, secs + 1):
        t_minus, pct = t - secs, t * 100 // secs
        bar = (char * (t * width // secs)).ljust(width)
        remaining = f"{t_minus}s" if t_minus else "done"
        print(f"\r[{bar}] ({t}s/{remaining}/{pct}%)", end="")
        time.sleep(1)
    print()


def crack_mt19937_seed(actually_wait=False):
    if actually_wait:
        secs = random.randint(40, 1000)
        print(f"Waiting {secs} seconds.")
        wait_progress(secs)
        print()

    now = int(time.time())
    rng = MT19337(now)

    print(f"Initialized MT19337 PRNG with seed of {now}.")

    if actually_wait:
        secs = random.randint(40, 1000)
        print()
        print(f"Waiting {secs} more seconds.")
        wait_progress(secs)

        later = int(time.time())
    else:
        later = now + random.randint(40, 1000)

    print()

    first_int32 = rng.rand()

    for utime in range(later - 1000, later + 1):
        rng.seed(utime)
        if rng.rand() == first_int32:
            return utime


def main():
    print("Cracking an MT19337 seed.")
    print()
    print("Actually wait, or just simulate waiting?")
    print("(Enter 'yes' exactly to wait. Anything else simulates.)")
    print()

    actually_wait = input("> ").lower() == "yes"
    print()

    print("Seed was:", crack_mt19937_seed(actually_wait))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


# Output:
#
#   Cracking an MT19337 seed.
#
#   Actually wait, or just simulate waiting?
#   (Enter 'yes' exactly to wait. Anything else simulates.)
#
#   > yes
#
#   Waiting 920 seconds.
#   [████████████████████████████████████████████████] (920s/done/100%)
#
#   Initialized MT19337 PRNG with seed of 1555172859.
#
#   Waiting 83 more seconds.
#   [████████████████████████████████████████████████] (83s/done/100%)
#
#   Seed was: 1555172859
#
