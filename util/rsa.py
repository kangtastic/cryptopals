# -*- coding: utf-8 -*-
import random

from .misc import egcd, get_prime, invmod, modexp, nth_root


# cf. NIST FIPS 186-4 §B.3.1, §B.3.3
# cf. github.com/Legrandin/pycryptodome/blob/master/lib/Crypto/PublicKey/RSA.py
def rsa(msg, key, as_bytes=True):
    """
    An implementation of the RSA cipher proper.
    :param Union[ByteString, int] msg: A message.
    :param Union[List, Tuple] key: A private key `[d, n]` or public key
        `[e, n]` to be used, respectively, for encryption or decryption.
    :param bool as_bytes: Whether to return a big-endian bytestring.
    :return: The resulting ciphertext or plaintext. By default, this is
        an `int` object.
    """
    if isinstance(msg, str):
        msg = msg.encode()

    if isinstance(msg, (bytes, bytearray)):
        msg = int.from_bytes(msg, "big")

    result = modexp(msg, *key)

    if as_bytes:
        byte_length = (result.bit_length() + 7) // 8
        result = result.to_bytes(byte_length, "big")

    return result


def make_rsa_keys(bits=1024, e=3, randbits=random.getrandbits):
    """
    Generates an RSA public/private key pair.

    Generated keys largely comply with the Digital Signature Standard (DSS)
    if both :param:`bits` and :param:`randbits` are provided, 2048 or 3072
    is provided as the former, and a `Callable` returning cryptographically
    secure random numbers is provided as the latter.
    :param int bits: The bit length of the RSA modulus.
    :param int e: The public verification exponent.
    :param Callable[int, int] randbits: A Callable taking an arbitrary
        bit length that returns a random number of that bit length.
    :return: A tuple `([e, n], [d, n])` containing the generated public and
        private keys in which `e` is the public verification exponent, `d`
        is the private signature exponent, and `n` is the RSA modulus, all
        as `int` objects.
    """
    # The tricky part not mentioned in the challenge description is that
    # any old primes p and q aren't guaranteed to work; `d`, i.e. the
    # multiplicative inverse of e and the totient of p and q, may not exist.
    def _constraint(prime, min_prime):
        return prime > min_prime and egcd(prime - 1, e)[0] == 1

    d = n = 1

    while n.bit_length() != bits and d < (1 << (bits // 2)):
        size_q = bits // 2
        size_p = bits - size_q

        min_p = min_q = nth_root(1 << (2 * size_q - 1), 2)
        if size_q != size_p:
            min_p = nth_root(1 << (2 * size_p - 1), 2)
        min_distance = 1 << (bits // 2 - 100)

        p = get_prime(size_p, randbits=randbits)
        while not _constraint(p, min_p):
            p = get_prime(size_p, randbits=randbits)

        q = get_prime(size_q, randbits=randbits)
        while not (_constraint(q, min_q) and (abs(q - p) > min_distance)):
            q = get_prime(size_q, randbits=randbits)

        n = p * q

        # Euler's totient.
        # totient = (p - 1) * (q - 1)

        # Carmichael's totient. Thanks, CRT!
        totient = ((p - 1) * (q - 1)) // egcd(p - 1, q - 1)[0]

        d = invmod(e, totient)

    return [e, n], [d, n]
