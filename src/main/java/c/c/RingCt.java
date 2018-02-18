package c.c;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public class RingCt {

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
    ECPoint I = hash.curveHash(myKey.publicKey()).multiply(myKey.privateKey());

    ECPoint L1 = g.multiply(alpha);
    ECPoint R1 = hash.curveHash(myKey.publicKey()).multiply(alpha);
    BigInteger c2 = hash.fieldHash(message, L1, R1);

    SigStep step1 = new SigStep(L1, R1, c2);
    SigStep step2 = step(I, message, step1, p2, s2);
    SigStep step0 = step(I, message, step2, p0, s0);

    BigInteger s1 = alpha.subtract(step0.cppi().add(myKey.privateKey())).mod(l);
    BigInteger c0 = step2.cppi();

    return new SignedMessage(message, I, c0, s0, s1, s2, p0, myKey.publicKey(), p2);
  }

  private SigStep step(
      ECPoint I,
      byte[] message,
      SigStep previous,
      ECPoint pi,
      BigInteger si) {
    ECPoint Li = g.multiply(si).add(pi.multiply(previous.cppi()));
    ECPoint Ri = hash.curveHash(pi).multiply(si).add(I.multiply(previous.cppi()));
    BigInteger cppi = hash.fieldHash(message, Li, Ri);
    return new SigStep(Li, Ri, cppi);
  }

  public boolean verify(SignedMessage signedMessage) {
    byte[] m = signedMessage.message();
    ECPoint I = signedMessage.keyImage();
    ECPoint p0 = signedMessage.p0();
    BigInteger s0 = signedMessage.s0();
    ECPoint L0 = g.multiply(s0).add(p0.multiply(signedMessage.c0()));
    ECPoint R0 = hash.curveHash(p0).multiply(s0).add(I.multiply(signedMessage.c0()));
    BigInteger c1 = hash.fieldHash(m, L0, R0);
    SigStep step0 = new SigStep(L0, R0, c1);
    SigStep step1 = step(I, m, step0, signedMessage.p1(), signedMessage.s1());
    SigStep step2 = step(I, m, step1, signedMessage.p2(), signedMessage.s2());
    BigInteger c3 = step2.cppi();
    return c3.equals(step0.cppi());
  }
}
