# -*- coding: utf-8 -*-
import base64
import random
import re
from textwrap import wrap

# English character relative frequencies. Some guessing was required.
# cf. https://en.wikipedia.org/wiki/Letter_frequency
# cf. https://mdickens.me/typing/letter_frequency.html
CHAR_FREQS = {
    b" ": 14,
    b"e": 12.702,
    b"t": 9.056,
    b"a": 8.167,
    b"o": 7.507,
    b"i": 6.966,
    b"n": 6.749,
    b"s": 6.327,
    b"h": 6.094,
    b"r": 5.987,
    b"d": 4.253,
    b"l": 4.025,
    b"c": 2.782,
    b"u": 2.758,
    b"m": 2.406,
    b"w": 2.360,
    b"f": 2.228,
    b"g": 2.015,
    b"y": 1.974,
    b"p": 1.929,
    b"b": 1.492,
    b",": 1.321,
    b".": 1.149,
    b"v": 0.978,
    b"k": 0.772,
    b"'": 0.617,
    b'"': 0.463,
    b"-": 0.308,
    b"j": 0.153,
    b"x": 0.150,
    b"q": 0.095,
    b"z": 0.074,
}

# Lookup table for hexdigits.
HEX_DIGIT = (
    b"0",
    b"1",
    b"2",
    b"3",
    b"4",
    b"5",
    b"6",
    b"7",
    b"8",
    b"9",
    b"a",
    b"b",
    b"c",
    b"d",
    b"e",
    b"f",
)

# Regular expression to search for/parse PKCS15 padding.
PKCS15_PADDED = re.compile(rb"^\x00\x02[\x01-\xff]{8,}\x00(.+)$")


# String analysis.
def englishness(bs):
    """Scores a bytestring on its similarity to English text."""
    return sum(CHAR_FREQS.get(bytes([b]), 0) for b in bs.lower())


def is_hexstring(string):
    """
    Determines if a string is a hexstring.
    :param Union[ByteString, str] string: A string.
    :return: Whether the string's length is even and all of its characters
        are in [0-9a-fA-f].
    """
    if isinstance(string, str):
        string = string.encode()
    return not len(string) % 2 and all(
        0x30 <= c <= 0x39 or 0x61 <= c <= 0x66 for c in string.lower()
    )


# String conversions and related.
def byte_length(n):
    """Finds the byte length of an `int` object."""
    return (n.bit_length() + 7) // 8


def from_bytes(bs):
    """Unpacks an unsigned int from a big-endian bytestring."""
    return int.from_bytes(bs, "big")


def hexstring_to_b64(hexstring, as_str=False):
    """
    Convert a hexstring to base64.
    :param str hexstring: A hex string as a `str` object.
    :param bool as_str: Whether to return the result as a `str` object.
    :return: The base64 representation of the hexstring as a bytestring
        or `str` object, depending on :param:`bool`.
    """
    result = base64.b64encode(bytes.fromhex(hexstring))
    if as_str:
        result = result.decode()
    return result


def int_to_hexbyte(n):
    """Like `hex()` for values 0-255, but as bytes and without the `0x`."""
    return HEX_DIGIT[n >> 4] + HEX_DIGIT[n & 0xF]


def to_bytes(*nums):
    """Packs one or more ints into a single concatenated big-endian bytestring."""
    nums = (nums,) if isinstance(nums, int) else nums
    return b"".join(n.to_bytes(byte_length(n), "big") for n in nums)


def to_str(n):
    return "".join(chr(b) for b in to_bytes(n) if chr(b).isprintable())


def to_hexstring(string):
    if isinstance(string, str):
        string = string.encode()
    return b"".join(map(int_to_hexbyte, string)).decode()


# Padding.
def pad_pkcs7(bs, size=16):
    bs = bytes(map(ord, bs)) if isinstance(bs, str) else bs

    if not len(bs) % size:
        return bs

    pad = size - (len(bs) % size)
    return bs + bytes(pad for _ in range(pad))


def unpad_pkcs7(ptext, bsize=16, assume_padded=False):
    pad = ptext[-1]
    if 0 < pad < bsize or assume_padded:
        if sum(ptext[-pad:]) == (pad ** 2):
            return ptext[:-pad]
        raise ValueError("Invalid PKCS#7 padding")
    return ptext


# cf. IETF RFC 4880 §13.1.1
def pad_pkcs15(ptext, bsize, as_bytes=True):
    if isinstance(ptext, str):
        ptext = ptext.encode()
    elif isinstance(ptext, int):
        ptext = to_bytes(ptext)

    l = len(ptext)
    if l > bsize - 11:
        raise ValueError(f"Message is too long for a block size of {bsize}.")

    pad = bytes(random.randint(1, 255) for _ in range(bsize - l - 3))
    ptext = b"\x00\x02" + pad + b"\x00" + ptext

    return ptext if as_bytes else int.from_bytes(ptext, "big")


# cf. IETF RFC 4880 §13.1.2
def unpad_pkcs15(padded, bsize):
    if isinstance(padded, str):
        ptext = padded.encode()
    elif isinstance(padded, int):
        ptext = to_bytes(padded)
    else:
        ptext = padded

    ptext = ptext.rjust(bsize, b"\x00")

    match = PKCS15_PADDED.match(ptext)
    if match:
        return match[1]

    raise ValueError(f"Message is not PKCS#1 1.5 padded.")


def print_indent(*msgs, width=66, as_hex=True):
    if not isinstance(msgs, (list, tuple)):
        msgs = (msgs,)

    print()

    for msg in msgs:
        if as_hex:
            msg = to_hexstring(msg)

        if isinstance(msg, (bytes, bytearray)):
            msg = msg.decode()
        elif isinstance(msg, int):
            msg = str(msg)

        for line in wrap(msg, width=width):
            print(" " * 4 + line)

    print()


# XOR.
def single_byte_xor(bs, key=False):
    if isinstance(bs, str):
        bs = bs.encode()

    result, high_score = 0 if key else b"", 0

    for n in range(256):
        candidate = bytes(b ^ n for b in bs)
        score = englishness(candidate)
        if score > high_score:
            result, high_score = n if key else candidate, score

    return bytes([result]) if key else result


def repeating_key_xor(bs, key):
    bs = bs.encode() if isinstance(bs, str) else bs
    key = key.encode() if isinstance(key, str) else key
    return bytes(bs[i] ^ key[i % len(key)] for i in range(len(bs)))
