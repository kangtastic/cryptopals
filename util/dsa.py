# -*- coding: utf-8 -*-
import random

from .misc import invmod, modexp
from .sha1 import SHA1
from .text import from_bytes

# We won't be generating DSA domain parameters, but from the bit lengths of
# p and q, we can tell that [L, N] is [1024, 160], and that we're using SHA1.
P = 0x800000000000000089E1855218A0E7DAC38136FFAFA72EDA7859F2171E25E65EAC698C1702578B07DC2A1076DA241C76C62D374D8389EA5AEFFD3226A0530CC565F3BF6B50929139EBEAC04F48C3C84AFB796D61E5A4F9A8FDA812AB59494232C7D2B4DEB50AA18EE9E132BFA85AC4374D7F9091ABC3D015EFC871A584471BB1
Q = 0xF4F47F05794B256174BBA6E9B396A7707E563C5B
G = 0x5958C9D3898B224B12672C0B98E06C60DF923CB8BC999D119458FEF538B8FA4046C8DB53039DB620C094C9FA077EF389B5322A559946A71903F990F1F7E0E025E2D7F7CF494AFF1A0470F5B64C36B625A097F1651FE775323556FE00B3608C887892878480E99041BE601A62166CA6894BDD41A7054EC89F756BA9FC95302291


def make_dsa_keys(p=P, q=Q, g=G):
    """Return public and private keys for a single DSA user."""
    x = random.randrange(1, q)
    y = modexp(g, x, p)
    return [y, x]  # Public and private, in that order.


# cf. NIST FIPS 186-4 §4.6
def dsa_sign(bs, privkey, k=None, p=P, q=Q, g=G):
    x, z = privkey, from_bytes(SHA1(bs).digest())

    r, s, need_k = 0, 0, not k
    while not r and not s:
        if need_k:
            k = random.randrange(1, q)
        need_k = True

        k_inv = invmod(k, q)  # modexp(k, q - 2, q) also works.
        if k_inv is None:
            continue

        r = modexp(g, k, p) % q
        if not r:
            continue

        s = (k_inv * (z + x * r)) % q

    return [r, s]


# cf. NIST FIPS 186-4 §4.7
def dsa_verify(bs, sig, pubkey, p=P, q=Q, g=G):
    r, s = sig

    if not 0 < r < q or not 0 < s < q:
        return False

    w, y, z = invmod(s, q), pubkey, from_bytes(SHA1(bs).digest())
    u1, u2 = (z * w) % q, (r * w) % q

    v = (modexp(g, u1, p) * modexp(y, u2, p) % p) % q

    return v == r
