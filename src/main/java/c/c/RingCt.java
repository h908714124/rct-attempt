package c.c;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.List;

public class RingCt {

  private final ECPoint g;

  private final List<ECPoint> pubkeys;

  private final KeyPair myKey;

  private final Hash hash;

  public RingCt(
      ECPoint g,
      List<ECPoint> pubkeys,
      KeyPair myKey,
      Hash hash) {
    this.g = g;
    this.pubkeys = pubkeys;
    this.myKey = myKey;
    this.hash = hash;
  }

  public String sign(byte[] message) {
    BigInteger s0 = new BigInteger("efe734dbde78c0b30a9170bf99bde2499d320f4c88e125fa71afbc000d5e120", 16);
    BigInteger alpha = new BigInteger("25a7b8a6d38b9eaa2b7f378928538bc2393fc512ed106369fc2fce6d554a3b8", 16);
    BigInteger s2 = new BigInteger("c292aeddc03e452697484b598870e59656ba6783a1c5d36f50623f39be8f077", 16);
    ECPoint I = hash.curveHash(myKey.publicKey()).multiply(myKey.privateKey());
    ECPoint L1 = g.multiply(alpha);
    ECPoint R1 = hash.curveHash(myKey.publicKey()).multiply(alpha);
    BigInteger c2 = hash.fieldHash(message, L1, R1);
    return null;
  }
}
