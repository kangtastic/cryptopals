#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Clone an MT19937 RNG from its output
#
# The internal state of MT19937 consists of 624 32-bit integers.
#
# For each batch of 624 outputs, MT permutes that internal state. By permuting
# state regularly, MT19937 achieves a period of 2**19937, which is Big.
#
# Each time MT19937 is tapped, an element of its internal state is subjected
# to a tempering function that diffuses bits through the result.
#
# The tempering function is invertible; you can write an "untemper" function
# that takes an MT19937 output and transforms it back into the corresponding
# element of the MT19937 state array.
#
# To invert the temper transform, apply the inverse of each of the operations
# in the temper transform in reverse order. There are two kinds of operations
# in the temper transform each applied twice; one is an XOR against a
# right-shifted value, and the other is an XOR against a left-shifted value
# AND'd with a magic number. So you'll need code to invert the "right" and the
# "left" operation.
#
# Once you have "untemper" working, create a new MT19937 generator, tap it for
# 624 outputs, untemper each of them to recreate the state of the generator,
# and splice that state into a new instance of the MT19937 generator.
#
# The new "spliced" generator should predict the values of the original.
#
# Stop and think for a second.
#
#   How would you modify MT19937 to make this attack hard? What would happen
#   if you subjected each tempered output to a cryptographic hash?
#
import random
import sys

sys.path.append("..")

from util.mt19937 import MT19337


def untemper_step(value, shift, mask=None):
    """
    Undo a step in the MT19337 PRNG's temper function.

    When a MT19337 PRNG is tapped, an element of its internal state,
    `y`, is returned after being "tempered" as follows:

        y ^= (y >> u) & d
        y ^= (y << s) & b
        y ^= (y << t) & c
        y ^= y >> l

    where the other variables are magic constants or bitmasks.

    Untempering a MT19337 output may be achieved with repeated calls
    to this function.

    :param value: The result of the tempering step.
    :param shift: The number of bitshift bits in the tempering step.
        If positive, we are undoing a right shift; if negative, left.
    :param mask: The bitmask used in the tempering step (optional).
    :return: The original input value to a tempering step.
    """

    def do_shift(v, n):
        return v >> n if n >= 0 else v << -n

    undoing_rshift = shift >= 0  # Are we undoing a right shift?
    mask = mask if mask is not None else MT19337.width_mask

    result = 0

    for i, _ in enumerate(range(0, MT19337.w, abs(shift))):
        value_mask = (1 << abs(shift)) - 1
        if undoing_rshift:
            vm_shift = MT19337.w - ((i + 1) * shift)
            value_mask = do_shift(value_mask, -vm_shift)
        else:
            value_mask = MT19337.int32(do_shift(value_mask, i * shift))
        result_mask = do_shift(value_mask, -shift)

        value_bits = value & value_mask
        result_bits = do_shift(result & result_mask, shift) & mask
        result |= value_bits ^ result_bits

    return result


def untemper(value):
    value = untemper_step(value, MT19337.l)
    value = untemper_step(value, -MT19337.t, MT19337.c)
    value = untemper_step(value, -MT19337.s, MT19337.b)
    value = untemper_step(value, MT19337.u, MT19337.d)
    return value


def main():
    print(f"Creating two MT19337 PRNGs, RNG1 and RNG2.")
    seed = random.getrandbits(32)
    rng1, rng2 = MT19337(seed), MT19337()

    n = random.randint(1 << 14, 1 << 21)

    print(f"Extracting {n} outputs from RNG1.")
    for _ in range(n):
        rng1.rand()

    print("Cloning RNG1 to RNG2.")
    print()

    rng2.MT = [untemper(rng1.rand()) for _ in range(624)]
    rng2.index = MT19337.n  # 624

    print("Next 10 outputs from RNG1 and RNG2:")
    print()

    for _ in range(10):
        n1, n2 = map(lambda n: str(n).ljust(10), (rng1.rand(), rng2.rand()))
        print(f"    {n1} {n2}")

    print()

    n = random.randint(1 << 14, 1 << 21)
    print(f"Next {n} outputs from both are the same: ", end="")
    print(all(rng1.rand() == rng2.rand() for _ in range(n)))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


# Output:
#
#   Creating two MT19337 PRNGs, RNG1 and RNG2.
#   Extracting 1618407 outputs from RNG1.
#   Cloning RNG1 to RNG2.
#
#   Next 10 outputs from RNG1 and RNG2:
#
#       3170173271 3170173271
#       3615970256 3615970256
#       2704161144 2704161144
#       2400086730 2400086730
#       987167529  987167529
#       217833030  217833030
#       636298567  636298567
#       771678000  771678000
#       674145305  674145305
#       818643669  818643669
#
#   Next 1466690 outputs from both are the same: True
#
