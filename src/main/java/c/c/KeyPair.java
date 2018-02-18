package c.c;

import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

final class KeyPair {

  private final ECParameterSpec curve;

  // private key
  private final BigInteger x;

  KeyPair(
      ECParameterSpec curve,
      BigInteger x) {
    this.curve = curve;
    this.x = x;
  }

  ECPoint publicKey() {
    return curve.getG().multiply(x);
  }

  BigInteger privateKey() {
    return x;
  }
}
