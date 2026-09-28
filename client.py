"""Schnorr Signature & NIZK Identification Scheme.
100% Python Standard Library.
"""

import hashlib
import secrets

class Secp256k1Curve:
    P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    A = 0
    B = 7
    Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    @classmethod
    def point_add(cls, p1, p2):
        if p1 is None:
            return p2
        if p2 is None:
            return p1
        x1, y1 = p1
        x2, y2 = p2
        if x1 == x2 and y1 != y2:
            return None
        if x1 == x2 and y1 == y2:
            m = (3 * x1 * x1 + cls.A) * pow(2 * y1, cls.P - 2, cls.P) % cls.P
        else:
            m = (y2 - y1) * pow(x2 - x1, cls.P - 2, cls.P) % cls.P
        x3 = (m * m - x1 - x2) % cls.P
        y3 = (m * (x1 - x3) - y1) % cls.P
        return (x3, y3)

    @classmethod
    def scalar_mult(cls, k: int, point=None):
        if point is None:
            point = (cls.Gx, cls.Gy)
        result = None
        addend = point
        while k:
            if k & 1:
                result = cls.point_add(result, addend)
            addend = cls.point_add(addend, addend)
            k >>= 1
        return result

class SchnorrSignature:
    """Schnorr digital signature over secp256k1."""
    curve = Secp256k1Curve

    @classmethod
    def sign(cls, priv_key: int, message: bytes) -> tuple:
        k = secrets.randbelow(cls.curve.N - 1) + 1
        R = cls.curve.scalar_mult(k)
        Rx, _ = R
        pub = cls.curve.scalar_mult(priv_key)
        Px, _ = pub
        h = hashlib.sha256(Rx.to_bytes(32, 'big') + Px.to_bytes(32, 'big') + message).digest()
        e = int.from_bytes(h, 'big') % cls.curve.N
        s = (k + e * priv_key) % cls.curve.N
        return (R, s)

    @classmethod
    def verify(cls, pub_point: tuple, message: bytes, signature: tuple) -> bool:
        R, s = signature
        Rx, _ = R
        Px, _ = pub_point
        h = hashlib.sha256(Rx.to_bytes(32, 'big') + Px.to_bytes(32, 'big') + message).digest()
        e = int.from_bytes(h, 'big') % cls.curve.N
        sG = cls.curve.scalar_mult(s)
        eP = cls.curve.scalar_mult(e, pub_point)
        R_plus_eP = cls.curve.point_add(R, eP)
        return sG == R_plus_eP
