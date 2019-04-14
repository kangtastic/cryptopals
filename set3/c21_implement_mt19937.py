#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Implement the MT19937 Mersenne Twister RNG
#
# You can get the psuedocode for this from Wikipedia.
#
# If you're writing in Python, Ruby, or (gah) PHP, your language is probably
# already giving you MT19937 as "rand()"; _don't use rand()_. Write the RNG
# yourself.
#
import sys

sys.path.append("..")

from util.mt19937 import MT19337


def main():
    print("Enter a seed for our MT19337 PRNG.")
    print()

    while True:
        try:
            seed = int(input("> "))
        except ValueError:
            pass
        else:
            print()
            break

    print("Seed:", seed)
    print()

    rng, outputs = MT19337(), []

    for _ in range(2):
        rng.seed(seed)
        outputs.append([rng.rand() for _ in range(5)])

    print("First 5 outputs:")
    print()
    for n in outputs[0]:
        print(f"    {n}")
    print()

    print(
        "Reseeding with the same seed results in the same output:",
        all(n1 == n2 for n1, n2 in zip(*outputs)),
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


# Output:
#
#   Enter a seed for our MT19337 PRNG.
#
#   > asfdfadfafdffa
#   > 12345
#
#   Seed: 12345
#
#   First 5 outputs:
#
#       3992670690
#       3823185381
#       1358822685
#       561383553
#       789925284
#
#   Reseeding with the same seed results in the same output: True
#
