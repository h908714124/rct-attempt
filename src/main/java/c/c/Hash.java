package c.c;

import org.bouncycastle.crypto.digests.KeccakDigest;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public class Hash {

  private final KeccakDigest keccak;

  private final ECParameterSpec curve;

  public Hash(
      KeccakDigest keccak,
      ECParameterSpec curve) {
    this.keccak = keccak;
    this.curve = curve;
  }

  public ECPoint curveHash(ECPoint point) {
    byte[] bytes = point.getEncoded(false);
    keccak.update(bytes, 0, bytes.length);
    int i = curve.getN().bitLength();
    while (i % 8 != 0) {
      ++i;
    }
    byte[] out = new byte[i];
    keccak.doFinal(out, 0);
    return curve.getG().multiply(new BigInteger(out));
  }

  public BigInteger fieldHash(byte[] message, ECPoint a, ECPoint b) {
    byte[] ba = a.getEncoded(false);
    byte[] bb = b.getEncoded(false);
    keccak.update(message, 0, message.length);
    keccak.update(ba, 0, ba.length);
    keccak.update(bb, 0, bb.length);
    BigInteger q = curve.getCurve().getField().getCharacteristic();
    int i = q.bitLength();
    while (i % 8 != 0) {
      ++i;
    }
    byte[] out = new byte[i];
    keccak.doFinal(out, 0);
    return new BigInteger(out).mod(q);
  }
}
