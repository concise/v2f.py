"""
Provide some cryptographic algorithms and related functions that
are commonly used by U2F authenticators and U2F relying parties.
"""

__all__ = [
    'generate_sha256_p256ecdsa_signature',
    'verify_sha256_p256ecdsa_signature',
    'generate_p256ecdsa_keypair',
    'verify_uncompressed_p256ecdsa_publickey',
    'x509encode_p256ecdsa_publickey',
    'x509decode_p256ecdsa_publickey',
    'compress_p256ecdsa_publickey',
    'uncompress_p256ecdsa_publickey',
    'extract_one_der_encoded_value',
    'sha256',
    'hmacsha256',
]


import hashlib
import hmac


b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
xG = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
yG = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5


def generate_p256ecdsa_keypair(entropy):
    """Generate a new key pair from the provided entropy."""
    x = next(rfc6979sha256p256csprng(entropy))
    Q = mul(x)
    return encode_privatekey(x), encode_publickey(Q, use_compression=False)


def verify_uncompressed_p256ecdsa_publickey(publickey):
    """Determine if the provided public key is well-formed."""
    try:
        decode_publickey(publickey, allow_compression=False)
        return True
    except ValueError:
        return False


def compress_p256ecdsa_publickey(publickey):
    """Convert a public key into its 33-byte compressed form.

    Raise ValueError if the provided public key is ill-formed.
    """
    Q = decode_publickey(publickey, allow_compression=True)
    return encode_publickey(Q, use_compression=True)


def uncompress_p256ecdsa_publickey(publickey):
    """Convert a public key into its 65-byte uncompressed form.

    Raise ValueError if the provided public key is ill-formed.
    """
    Q = decode_publickey(publickey, allow_compression=True)
    return encode_publickey(Q, use_compression=False)


def x509encode_p256ecdsa_publickey(publickey):
    """Generate a certificate with specified subject public key.

    Raise ValueError if the provided public key is ill-formed.
    """
    decode_publickey(publickey, allow_compression=False)
    return SEQUENCE([
        SEQUENCE([
            bytes.fromhex('a0 03 020102'),
            bytes.fromhex('02 01 00'),
            bytes.fromhex('30 0a 06 08 2a8648ce3d040302'),
            SEQUENCE([SET([SEQUENCE([
                bytes.fromhex('06 03 550403'),
                UTF8STRING('No Such Authority'),  # issuer
            ])])]),
            SEQUENCE([
                UTCTIME(b'160101000000Z'),  # notbefore 2016/01/01
                UTCTIME(b'360101000000Z'),  # notafter  2036/01/01
            ]),
            SEQUENCE([SET([SEQUENCE([
                bytes.fromhex('06 03 550403'),
                UTF8STRING('This U2F Device Does Not Do Attestation'),  # subj
            ])])]),
            SEQUENCE([
                bytes.fromhex('301306072a8648ce3d020106082a8648ce3d030107'),
                BITSTRING(publickey),
            ]),
        ]),
        bytes.fromhex('30 0a 06 08 2a8648ce3d040302'),
        bytes.fromhex('03 09 003006020103020101'),
    ])


def x509decode_p256ecdsa_publickey(certificate):
    """Extract subject public key from the provided certificate.

    Raise ValueError if the provided certificate is ill-formed.
    """
    tbscert, _, _ = DER_decode_one_SEQUENCE(certificate)
    _, _, _, _, _, _, pkinfo, *_ = DER_decode_one_SEQUENCE(tbscert)
    alg, pkbits = DER_decode_one_SEQUENCE(pkinfo)
    P256PUBKEY = bytes.fromhex('301306072a8648ce3d020106082a8648ce3d030107')
    if not (alg == P256PUBKEY and pkbits[:3] == b'\x03\x42\x00'):
        raise ValueError
    Q = decode_publickey(pkbits[3:], allow_compression=True)
    return encode_publickey(Q, use_compression=False)


def generate_sha256_p256ecdsa_signature(privatekey, message):
    """Generate an ECDSA signature for the provided message.

    Raise ValueError if the provided private key is ill-formed.
    """
    x = decode_privatekey(privatekey)
    e = sha256p256(message)
    for k in ephemeral_keys_from_privatekey_and_messagehash(x, e):
        R = mul(k)
        r = R[0] % n
        s = (e + r * x % n) * inv(k, n) % n
        if r != 0 and s != 0:
            return SEQUENCE([INTEGER(r), INTEGER(s)])


def verify_sha256_p256ecdsa_signature(publickey, message, signature):
    """Determine if the signature is valid for the message.

    Raise ValueError if the provided public key is ill-formed.
    """
    Q = decode_publickey(publickey, allow_compression=True)
    e = sha256p256(message)
    try:
        _r, _s = DER_decode_one_SEQUENCE(signature)
        r = DER_decode_one_INTEGER(_r)
        s = DER_decode_one_INTEGER(_s)
    except ValueError:
        return False
    if not (0 < r < n and 0 < s < n):
        return False
    si = inv(s, n)
    t, u = e * si % n, r * si % n
    R = add(mul(t), mul(u, Q))
    return R is not None and R[0] % n == r


def extract_one_der_encoded_value(octets):
    """Extract the leading DER encoded value.

    Return a tuple of two octet strings where the first one is
    the extracted DER encoded value and the second one contains
    all the subsequent uninterpreted octets.

    Raise ValueError if the provided octet string is ill-formed.
    """
    T, L, V, Z = DER_decode_one_something(octets)
    return T + L + V, Z


def sha256(msg):
    """Generate a SHA-256 hash."""
    return hashlib.sha256(msg).digest()


def hmacsha256(key, msg):
    """Generate an HMAC-SHA-256 message authentication code."""
    return hmac.new(key, msg, 'sha256').digest()


def sha256p256(msg):
    return int.from_bytes(sha256(msg), 'big') % n


def ephemeral_keys_from_privatekey_and_messagehash(x, e):
    yield from rfc6979sha256p256csprng(
        x.to_bytes(32, 'big') +
        e.to_bytes(32, 'big')
    )


def rfc6979sha256p256csprng(entropy):
    V = b'\x01' * 32
    K = b'\x00' * 32
    K = hmacsha256(K, V + b'\x00' + entropy)
    V = hmacsha256(K, V)
    K = hmacsha256(K, V + b'\x01' + entropy)
    V = hmacsha256(K, V)
    while True:
        T = hmacsha256(K, V)
        k = int.from_bytes(T, 'big')
        if 0 < k < n:
            yield k
        K = hmacsha256(K, V + b'\x00')
        V = hmacsha256(K, V)


def INTEGER(i):
    length = 1
    while True:
        try:
            return DER_encode(0x02, i.to_bytes(length, 'big', signed=True))
        except OverflowError:
            length += 1


def BITSTRING(octets, number_of_trailing_unused_bits=0):
    assert number_of_trailing_unused_bits in [0, 1, 2, 3, 4, 5, 6, 7]
    return DER_encode(0x03, bytes([number_of_trailing_unused_bits]) + octets)


def UTF8STRING(s):
    return DER_encode(0x0c, s.encode())


def UTCTIME(octets):
    return DER_encode(0x17, octets)


def SEQUENCE(iterable):
    return DER_encode(0x30, b''.join(iterable))


def SET(iterable):
    return DER_encode(0x31, b''.join(iterable))


def DER_encode(tag, value):
    identifier_octets = bytes([tag])
    length_octets = DER_encode_a_length(len(value))
    contents_octets = value
    return b''.join([identifier_octets, length_octets, contents_octets])


def DER_encode_a_length(length):
    assert type(length) is int and length >= 0 and length.bit_length() <= 1008
    if length < 128:
        return bytes([length])
    if length < 256:
        return bytes([0x81, length])
    llen = 2
    while True:
        if length < 2 ** (8*llen):
            return bytes([0x80 | llen]) + length.to_bytes(llen, 'big')
        llen += 1


def DER_decode_one_INTEGER(octets):
    T, L, V, tail = DER_decode_one_something(octets)
    if not (T == b'\x02' and tail == b''):
        raise ValueError
    if len(V) == 0:
        raise ValueError
    if len(V) >= 2 and (
        (V[0] == 0b00000000 and V[1] >> 7 == 0) or
        (V[0] == 0b11111111 and V[1] >> 7 == 1)
    ):
        raise ValueError
    return int.from_bytes(V, 'big', signed=True)


def DER_decode_one_SEQUENCE(octets):
    T, L, V, tail = DER_decode_one_something(octets)
    if not (T == b'\x30' and tail == b''):
        raise ValueError
    elms, tail = [], V
    while tail != b'':
        T, L, V, tail = DER_decode_one_something(tail)
        elms.append(T + L + V)
    return tuple(elms)


def DER_decode_one_something(octets):
    T, tail1 = DER_extract_identifier_octets(octets)
    L, tail2 = DER_extract_length_octets(tail1)
    V_length = DER_decode_length_octets(L)
    V, tail3 = tail2[:V_length], tail2[V_length:]
    return T, L, V, tail3


def DER_extract_identifier_octets(stream):
    try:
        assert len(stream) >= 1
        if stream[0] & 0b00011111 != 0b00011111:
            return stream[:1], stream[1:]
        else:
            assert len(stream) >= 2
            l = next(i for i, e in enumerate(stream[1:]) if e >> 7 == 0)
            if l == 0:
                assert stream[1] >= 0b00011111
            else:
                assert stream[1] & 0b01111111 != 0
            return stream[:l+2], stream[l+2:]
    except AssertionError as x:
        raise ValueError from x
    except StopIteration as x:
        raise ValueError from x


def DER_extract_length_octets(stream):
    try:
        assert len(stream) >= 1
        if stream[0] >> 7 == 0:
            return stream[:1], stream[1:]
        else:
            l = stream[0] & 0b01111111
            assert 1 <= l <= 126
            assert len(stream) >= l + 1
            assert (l == 1 and stream[1] >= 128) or (l > 1 and stream[1] != 0)
            return stream[:l+1], stream[l+1:]
    except AssertionError as x:
        raise ValueError from x


def DER_decode_length_octets(length_octets):
    if length_octets[0] < 128:
        return length_octets[0]
    else:
        return int.from_bytes(length_octets[1:], 'big')


def encode_privatekey(x):
    return x.to_bytes(32, 'big')


def decode_privatekey(privatekey):
    x = int.from_bytes(privatekey, 'big')
    if not (len(privatekey) == 32 and 0 < x < n):
        raise ValueError
    return x


def encode_publickey(P, use_compression):
    """Convert a point not at infinity to an octet string."""
    if not use_compression:
        return b'\x04' + P[0].to_bytes(32, 'big') + P[1].to_bytes(32, 'big')
    elif P[1] % 2 == 0:
        return b'\x02' + P[0].to_bytes(32, 'big')
    else:
        return b'\x03' + P[0].to_bytes(32, 'big')


def decode_publickey(S, allow_compression):
    """Convert an octet string to a point not at infinity."""
    if len(S) == 65 and S[0] == 0x04:
        xP = int.from_bytes(S[1:33], 'big')
        yP = int.from_bytes(S[33:65], 'big')
        if xP < p and yP < p and (xP**3 - 3*xP + b - yP**2) % p == 0:
            return xP, yP
    if len(S) == 33 and S[0] in [0x02, 0x03] and allow_compression:
        xP = int.from_bytes(S[1:33], 'big')
        y_squared = (xP**3 - 3*xP + b) % p
        yP0, yP1 = sqrt(y_squared, p)
        if xP < p and yP0**2 % p == y_squared:
            return xP, (yP0 if S[0] % 2 == 0 else yP1)
    raise ValueError


def add(P1, P2):
    """Compute P1 + P2."""
    if P1 is None:
        return P2
    if P2 is None:
        return P1
    if P1[0] != P2[0]:  # x1 != x2  and  y1 != y2
        return affine_point_addition(P1, P2)
    if P1[1] == P2[1]:  # x1 == x2  and  y1 == y2 != 0 (i.e., y1 + y2 != 0)
        return affine_point_doubling(P1)
    return None  # x1 == x2  and  y1 != y2 (i.e., y1 + y2 == 0)


def affine_point_addition(P1, P2):
    x1, y1 = P1
    x2, y2 = P2
    v = ((y2 - y1) * inv(x2 - x1, p)) % p
    x3 = (v * v - x1 - x2) % p
    y3 = (v * (x1 - x3) - y1) % p
    return x3, y3


def affine_point_doubling(P1):
    x1, y1 = P1
    w = ((3 * x1 * x1 - 3) * inv(2 * y1, p)) % p
    x4 = (w * w - 2 * x1) % p
    y4 = (w * (x1 - x4) - y1) % p
    return x4, y4


def inv(a, m):
    """Compute 1/a mod m."""
    s, t, x2, x1, = a, m, 1, 0
    while t > 0:
        q, r = divmod(s, t)
        x = x2 - q * x1
        s, t, x2, x1 = t, r, x1, x
    return x2 if x2 > 0 else x2 + m


def sqrt(a, m):
    """Compute two possible square roots of a mod m."""
    assert m & 0b11 == 0b11
    t = pow(a, (m + 1) >> 2, m)
    if t % 2 == 0:
        return t, m - t
    else:
        return m - t, t


def mul(k, P=None):
    """Compute [k]P where P is set to the base point when omitted."""
    P = (xG, yG) if P is None else P
    return montlad_scamul(k, P)


def montlad_scamul(k, P):
    # We never multiply the point at infinity in ECDSA
    assert P is not None

    # Either convert k to its modulo-n equivalence in the range [0, n-1]
    # or to its 258-bit fixed-length equivalence in the range [3n, 4n-1].
    k %= n

    # I'd like use a co-Z representation for all possible ([j]P, [j+1]P) pairs
    # where j is a non-negative integer.  However, I don't know a proper way to
    # represent a pair that contains the point at infinity when j or j+1 is
    # zero mod n.  To make things easier, I restrict j only to those integers
    # in the range [1, n-2] rather than [0, n-1] or [0, Infinity).
    if k == 0:
        return None
    if k == n - 1:
        return P[0], p - P[1]

    # k <- k + 3n if you want to have a fixed-length (258 bits) k.  That makes
    # Montgomery ladder time-constant at the cost of 2.5 more steps in average.
    # k += 0x2fffffffd00000002ffffffffffffffff36b4f008f546db8edb2d6048f5296ff3

    # Montgomery ladder with (X1, X2, Z) co-Z representation of ([j]P, [j+1]P)
    PP = co_z_encode(P)
    for bit in '{:b}'.format(k)[1:]:
        if bit == '0':
            co_z_zero_transform(PP)
        else:
            co_z_one_transform(PP)
    return co_z_decode(PP)


# P -> ([1]P, [2]P)
def co_z_encode(P):
    xD, yD = P
    # Here we apply a trick to reuse the co_z_one_transform() function given
    # the fact that x^3-3x+b is a quadratic nonresidue modulo p if x = 1
    _4b_ = 0x6b18d763a8ea4f9dcfaef555da621af194741ac2314ec3d8ef38f0f89f49812d
    PP = [1, xD, xD, -3, _4b_, xD, yD]
    co_z_one_transform(PP)
    PP[0] = PP[2]
    return PP


# ([j]P, [j+1]P) -> ([2j]P, [2j+1]P)
def co_z_zero_transform(PP):
    PP[0], PP[1] = PP[1], PP[0]
    co_z_one_transform(PP)
    PP[0], PP[1] = PP[1], PP[0]


# ([j]P, [j+1]P) -> ([2j+1]P, [2j+2]P)
def co_z_one_transform(PP):
    X1, X2, TD, Ta, Tb, *_ = PP
    R2 = (X1 - X2) % p; R1 = (R2 * R2) % p; R2 = (X2 * X2) % p
    R3 = (R2 - Ta) % p; R4 = (R3 * R3) % p; R5 = (X2 + X2) % p
    R3 = (R5 * Tb) % p; R4 = (R4 - R3) % p; R5 = (R5 + R5) % p
    R2 = (R2 + Ta) % p; R3 = (R5 * R2) % p; R3 = (R3 + Tb) % p
    R5 = (X1 + X2) % p; R2 = (R2 + Ta) % p; R2 = (R2 - R1) % p
    X2 = (X1 * X1) % p; R2 = (R2 + X2) % p; X2 = (R5 * R2) % p
    X2 = (X2 + Tb) % p; X1 = (R3 * X2) % p; X2 = (R1 * R4) % p
    R2 = (R1 * R3) % p; R3 = (R2 * Tb) % p; R4 = (R2 * R2) % p
    R1 = (TD * R2) % p; R2 = (Ta * R4) % p; Tb = (R3 * R4) % p
    X1 = (X1 - R1) % p; TD = R1;            Ta = R2
    PP[0], PP[1], PP[2], PP[3], PP[4] = X1, X2, TD, Ta, Tb


# ([j]P, [j+1]P) -> [j]P
def co_z_decode(PP):
    X1, X2, TD, Ta, Tb, xD, yD = PP
    R1 = (TD * X1) % p; R2 = (R1 + Ta) % p; R3 = (X1 + TD) % p
    R4 = (R2 * R3) % p; R3 = (X1 - TD) % p; R2 = (R3 * R3) % p
    R3 = (R2 * X2) % p; R4 = (R4 - R3) % p; R4 = (R4 + R4) % p
    R4 = (R4 + Tb) % p; R2 = (TD * TD) % p; R3 = (X1 * R2) % p
    R1 = (xD * R3) % p; R3 = (yD + yD) % p; R3 = (R3 + R3) % p
    X1 = (R3 * R1) % p; R1 = (R2 * TD) % p; Z_ = (R3 * R1) % p
    R2 = (xD * xD) % p; R3 = (R2 * xD) % p; X2 = (R3 * R4) % p
    Zi = inv(Z_, p);    xQ = (X1 * Zi) % p; yQ = (X2 * Zi) % p
    return xQ, yQ
