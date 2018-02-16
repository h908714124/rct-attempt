package c.c;

import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public class KeyPair {

  private final ECParameterSpec curve;

  // private key
  private final BigInteger x;

  public KeyPair(
      ECParameterSpec curve,
      BigInteger x) {
    this.curve = curve;
    this.x = x;
  }

  public ECPoint publicKey() {
    return curve.getG().multiply(x);
  }

  public BigInteger privateKey() {
    return x;
  }
}
