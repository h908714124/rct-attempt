package c.c;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

class SigStep {

  private final ECPoint Li;
  private final ECPoint Ri;
  private final BigInteger cppi;

  SigStep(ECPoint Li, ECPoint Ri, BigInteger cppi) {
    this.Li = Li;
    this.Ri = Ri;
    this.cppi = cppi;
  }

  public ECPoint Li() {
    return Li;
  }

  public ECPoint Ri() {
    return Ri;
  }

  public BigInteger cppi() {
    return cppi;
  }
}
