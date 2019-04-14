#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# ECB cut-and-paste
#
# Write a k=v parsing routine, as if for a structured cookie. The routine
# should take:
#
#   foo=bar&baz=qux&zap=zazzle
#
# ... and produce:
#
#   {
#     foo: 'bar',
#     baz: 'qux',
#     zap: 'zazzle'
#   }
#
# (you know, the object; I don't care if you convert it to JSON).
#
# Now write a function that encodes a user profile in that format, given an
# email address. You should have something like:
#
#   profile_for("foo@bar.com")
#
# ... and it should produce:
#
#   {
#     email: 'foo@bar.com',
#     uid: 10,
#     role: 'user'
#   }
#
# ... encoded as:
#
#   email=foo@bar.com&uid=10&role=user
#
# Your "profile_for" function should *not* allow encoding metacharacters
# (& and =). Eat them, quote them, whatever you want to do, but don't let
# people set their email address to "foo@bar.com&role=admin".
#
# Now, two more easy functions. Generate a random AES key, then:
#
#   A. Encrypt the encoded user profile under the key; "provide" that to the
#      "attacker".
#   B. Decrypt the encoded user profile and parse it.
#
# Using only the user input to profile_for() (as an oracle to generate "valid"
# ciphertexts) and the ciphertexts themselves, make a role=admin profile.
#
import sys

sys.path.append("..")

from util.aes import aes_ecb_decrypt, aes_ecb_encrypt, make_aes_key
from util.text import pad_pkcs7

KEY = make_aes_key()


def kv_parse(bs):
    s, dct = bs.decode(), {}
    for kv in s.split("&"):
        k, v = kv.split("=")
        dct.update({k: int(v) if v.isnumeric() else v})
    return dct


def profile_for(email):
    email = email.strip().replace("&", "").replace("=", "")
    return f"email={email}&uid=10&role=user".encode()


def provide_encrypted(email):
    return aes_ecb_encrypt(profile_for(email), KEY)


def parse_encrypted(ctext):
    return kv_parse(aes_ecb_decrypt(ctext, KEY))


def main():
    """Attacker function."""
    # len("email=herp@derp.com&uid=10&role=") => 32.
    # "user" in "role=user" then falls on a block boundary.
    email = "herp@derp.com"
    email_profile = provide_encrypted(email)
    email_obj = parse_encrypted(email_profile)

    # Now for the attack.
    # len("email=a@sdfj.com") => 16. "admin" then falls on a block
    # boundary for a email of "a@sdfj.comadmin<whatever>".
    padded = "a@sdfj.com" + pad_pkcs7("admin").decode() + "A" * 16
    padded_profile = provide_encrypted(padded)

    crafted_profile = email_profile[:32] + padded_profile[16:32]
    crafted_obj = parse_encrypted(crafted_profile)

    print(f"Object for {email}:")
    print()
    print(f"    {email_obj}")
    print()
    print("Crafted object:")
    print()
    print(f"    {crafted_obj}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


# Output:
#
#   Object for herp@derp.com:
#
#       {'email': 'herp@derp.com', 'uid': 10, 'role': 'user'}
#
#   Crafted object:
#
#       {'email': 'herp@derp.com', 'uid': 10, 'role': 'admin'}
#
