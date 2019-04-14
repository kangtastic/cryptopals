# -*- coding: utf-8 -*-
import os
import random

from Crypto.Util.number import sieve_base


# Multiprocessing.
def cpu_threads():
    """
    Suggest how many CPU threads should be used for multiprocessing.
    :return: 1, or 1 fewer than the number of threads in the affinity mask of
        the current process, whichever is greater.
    """
    return max(1, len(os.sched_getaffinity(0)) - 1)


# Math.
# cf. en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
def egcd(a, b):
    """
    An implementation of the extended Euclidean algorithm.
    :return: A tuple `(g, x, y)` such that ax + by == g == gcd(a, b).
    """
    x, x1 = 0, 1
    y, y1 = 1, 0
    while a != 0:
        q, b, a = b // a, a, b % a
        y, y1 = y1, y - q * y1
        x, x1 = x1, x - q * x1
    return b, x, y


# A translation into Python 3 of a translation into C of a Perl script.
# cf. rosettacode.org/wiki/Modular_inverse#C (second snippet)
def invmod(a, b):
    """
    Finds the multiplicative inverse of :param:`a` and :param:`b`.
    :return: An int `x` such that `ax % b == 1`.
    """
    b = abs(b)
    if a < 0:
        a = b - (-a % b)

    x, nx = 0, 1
    r, nr = b, a % b
    while nr:
        x, nx = nx, x - (r // nr) * nx
        r, nr = nr, r - (r // nr) * nr

    if r == 1:
        return x + b if x < 0 else x


# cf. Schneier, Bruce (1996). Applied Cryptography: Protocols, Algorithms, and
#       Source Code in C (2nd ed.). New York: Wiley. ISBN 978-0-471-11709-4.
def modexp(base, exponent, modulus):
    """
    Performs modular exponentiation.
    :return: (base ** exponent) % modulus
    """
    # NOTE: pow() in recent versions of Python 3 does the same thing.

    if modulus == 1:
        return 0

    result = 1
    base %= modulus
    while exponent:
        if exponent % 2:
            result = (result * base) % modulus
        exponent >>= 1
        base = (base ** 2) % modulus

    return result


# cf. https://stackoverflow.com/a/356206
def nth_root(x, n):
    """Finds the nearest integer root of a number."""
    upper = 1
    while upper ** n <= x:
        upper *= 2

    mid, lower = None, upper // 2

    while lower != upper:
        mid = (lower + upper) // 2
        mid_n = mid ** n
        if lower < mid and mid_n < x:
            lower = mid
        elif upper > mid and mid_n > x:
            upper = mid
        else:
            return mid

    if mid is not None:
        return mid + 1


# Prime generation.
# cf. en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test
# cf. github.com/Legrandin/pycryptodome/blob/master/lib/Crypto/Util/number.py
def is_prime(n, k=10):
    """
    An implementation of the Miller-Rabin primality test.
    :param int n: An odd integer > 3 to be tested for primality.
    :param int k: The number of rounds of testing to perform.
        The probability of a false positive for the default value
        of 10 is at most 1e-6.
    """

    # Check for divisibility by the first 10,000 known primes.
    for known_prime in sieve_base:
        if not (n % known_prime):
            return False

    # Write n as (2 ** r) * d + 1, with d odd.
    n_1 = n - 1  # "Pre-calculate n - 1, as it may be large."
    r, d = 0, n_1
    while not (d & 1):
        r, d = r + 1, d >> 1

    # Probability of false positive for k of 10 is at most 1e-6.
    tested = []
    for _ in range(k):
        a = random.randint(2, n - 2)
        while a in tested:
            a = random.randint(2, n - 2)
        tested.append(a)

        x = modexp(a, d, n)
        if x in (1, n_1):
            continue

        for _ in range(r - 1):
            x = modexp(x, x, n)
            if x == 1:
                return False
            if x == n_1:
                break
        else:
            return False

    return True


# cf. github.com/Legrandin/pycryptodome/blob/master/lib/Crypto/Util/number.py
def get_prime(bits, randbits=random.getrandbits):
    """
    Generates arbitrarily large primes.
    :param int bits: The bit length of the prime.
    :param Callable[int, int] randbits: A Callable taking an arbitrary
        bit length that returns a random number of that bit length.
    """
    n = randbits(bits)
    n |= 1 << bits - 1 | 1  # Set high and low order bits.
    while not is_prime(n):
        n += 2
    return n
