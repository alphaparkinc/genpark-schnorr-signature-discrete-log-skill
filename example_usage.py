from client import SchnorrSignature, Secp256k1Curve

def main():
    priv = 0xFEEDBEEF1234
    pub = Secp256k1Curve.scalar_mult(priv)
    msg = b"Agent swarm authorization token"
    sig = SchnorrSignature.sign(priv, msg)
    print("Signature verified:", SchnorrSignature.verify(pub, msg, sig))

if __name__ == "__main__":
    main()
