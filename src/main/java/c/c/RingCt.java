package c.c;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public final class RingCt {

  private final ECPoint g;

  private final BigInteger l;

  private final ECPoint p0;

  private final ECPoint p2;

  private final KeyPair myKey;

  private final Hash hash;

  public RingCt(
      ECPoint g,
      BigInteger l,
      ECPoint p0,
      ECPoint p2,
      KeyPair myKey,
      Hash hash) {
    this.g = g;
    this.l = l;
    this.p0 = p0;
    this.p2 = p2;
    this.myKey = myKey;
    this.hash = hash;
  }

  public SignedMessage sign(byte[] message) {
    BigInteger s0 = new BigInteger("efe734dbde78c0b30a9170bf99bde2499d320f4c88e125fa71afbc000d5e120", 16);
    BigInteger alpha = new BigInteger("25a7b8a6d38b9eaa2b7f378928538bc2393fc512ed106369fc2fce6d554a3b8", 16);
    BigInteger s2 = new BigInteger("c292aeddc03e452697484b598870e59656ba6783a1c5d36f50623f39be8f077", 16);
    ECPoint p1 = myKey.publicKey();
    ECPoint I = hash.curveHash(p1).multiply(myKey.privateKey());

    ECPoint L1 = g.multiply(alpha);
    ECPoint R1 = hash.curveHash(p1).multiply(alpha);
    BigInteger c2 = hash.fieldHash(message, L1, R1);

    SigStep step1 = new SigStep(L1, R1, c2);
    SigStep step2 = step(I, message, step1, p2, s2);
    SigStep step0 = step(I, message, step2, p0, s0);

    BigInteger c1 = step0.cppi();
    BigInteger s1 = alpha.subtract(c1.multiply(myKey.privateKey())).mod(l);
    BigInteger c0 = step2.cppi();

    return new SignedMessage(message, I, c0, s0, s1, s2, p0, p1, p2);
  }

  public boolean verify(SignedMessage signedMessage) {
    byte[] m = signedMessage.message();
    ECPoint I = signedMessage.keyImage();
    ECPoint p0 = signedMessage.p0();
    BigInteger s0 = signedMessage.s0();
    BigInteger c0 = signedMessage.c0();
    ECPoint L0 = g.multiply(s0).add(p0.multiply(c0));
    ECPoint R0 = hash.curveHash(p0).multiply(s0).add(I.multiply(c0));
    BigInteger c1 = hash.fieldHash(m, L0, R0);
    ECPoint p1 = signedMessage.p1();
    ECPoint p2 = signedMessage.p2();
    BigInteger s1 = signedMessage.s1();
    BigInteger s2 = signedMessage.s2();
    SigStep step0 = new SigStep(L0, R0, c1);
    SigStep step1 = step(I, m, step0, p1, s1);
    SigStep step2 = step(I, m, step1, p2, s2);
    BigInteger c3 = step2.cppi();
    if (!c3.equals(c0)) {
      return false;
    }
    if (!c1.equals(hash.fieldHash(m, step0.Li(), step0.Ri()))) {
      return false;
    }
    BigInteger c2 = step1.cppi();
    if (!c2.equals(hash.fieldHash(m, step1.Li(), step1.Ri()))) {
      return false;
    }
    if (!c0.equals(hash.fieldHash(m, step2.Li(), step2.Ri()))) {
      return false;
    }
    return true;
  }

  private SigStep step(
      ECPoint I,
      byte[] message,
      SigStep previous,
      ECPoint pi,
      BigInteger si) {
    BigInteger ci = previous.cppi();
    ECPoint Li = g.multiply(si).add(pi.multiply(ci));
    ECPoint Ri = hash.curveHash(pi).multiply(si).add(I.multiply(ci));
    BigInteger cppi = hash.fieldHash(message, Li, Ri);
    return new SigStep(Li, Ri, cppi);
  }
}
