# -*- coding: utf-8 -*-
from .misc import modexp

# cf. https://tools.ietf.org/html/rfc3526
# Prime and generator constants for DH Group 5 (1536-bit).
P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
G = 2


def dh_make_public_key(secret, p=P, g=G):
    """:return: A 1536-bit public key as a big-endian bytestring."""
    return modexp(g, secret, p).to_bytes(192, byteorder="big")


def dh_make_session_key(public_key, secret, p=P):
    """:return: A 1536-bit session key as a big-endian bytestring."""
    public_key = int.from_bytes(public_key, byteorder="big")
    session_key = modexp(public_key, secret, p).to_bytes(192, byteorder="big")
    return session_key
