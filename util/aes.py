# -*- coding: utf-8 -*-
import random
from collections import Counter

from Crypto.Cipher import AES

from .text import pad_pkcs7, repeating_key_xor, unpad_pkcs7


def make_aes_key(size=128):
    return random.getrandbits(size).to_bytes(size // 8, "big")


def unpad_pkcs7_aes(ptext):
    # Silently eat the ValueError raised by unpad_pkcs7 on bad padding.
    try:
        ptext = unpad_pkcs7(ptext)
    except ValueError:
        pass
    return ptext


# ECB mode.
def is_aes_ecb(ctext):
    ctr = Counter(ctext[i : i + 16] for i in range(0, len(ctext), 16))
    reps = ctr.most_common(1)[0][1]
    return reps > 1


def aes_ecb_encrypt(ptext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad_pkcs7(ptext))


def aes_ecb_decrypt(ctext, key, unpad=True):
    cipher = AES.new(key, AES.MODE_ECB)
    ptext = cipher.decrypt(ctext)
    return unpad_pkcs7_aes(ptext) if unpad else ptext


# CBC mode.
def aes_cbc_encrypt(ptext, key, iv=b"\x00" * 16):
    # `AES.MODE_ECB` isn't a typo; we're implementing CBC by hand.
    cipher = AES.new(key, AES.MODE_ECB)
    ptext, ctext, ct_block = pad_pkcs7(ptext), bytearray(), iv

    for i in range(0, len(ptext), 16):
        pt_block = repeating_key_xor(ptext[i : i + 16], ct_block)
        ct_block = cipher.encrypt(pt_block)
        ctext.extend(ct_block)

    return bytes(ctext)


def aes_cbc_decrypt(ctext, key, iv=b"\x00" * 16, unpad=True):
    # `AES.MODE_ECB` isn't a typo; we're implementing CBC by hand.
    cipher = AES.new(key, AES.MODE_ECB)
    ptext, ct_block = bytearray(), iv

    for i in range(0, len(ctext), 16):
        next_ct_block = ctext[i : i + 16]
        pt_block = repeating_key_xor(cipher.decrypt(next_ct_block), ct_block)
        ct_block = next_ct_block
        ptext.extend(pt_block)

    ptext = bytes(ptext)

    return unpad_pkcs7_aes(ptext) if unpad else ptext


# CTR mode.
def aes_ctr_pack(n):
    n %= (1 << 64) - 1
    return n.to_bytes(8, "little")


def aes_ctr(bstream, key, nonce=0):
    # `AES.MODE_ECB` isn't a typo; we're implementing CTR by hand.
    cipher, nonce = AES.new(key, AES.MODE_ECB), aes_ctr_pack(nonce)

    if isinstance(bstream, str):
        bstream = bstream.encode()

    result = bytearray()

    for count, i in enumerate(range(0, len(bstream), 16)):
        key_block = cipher.encrypt(nonce + aes_ctr_pack(count))
        result.extend(kb ^ sb for kb, sb in zip(key_block, bstream[i : i + 16]))

    return bytes(result)
