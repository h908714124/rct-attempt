package c.c;

import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

public class RingCt {

  final ECParameterSpec curve;

  final List<ECPoint> pubkeys;

  public RingCt(
      ECParameterSpec curve,
      List<ECPoint> pubkeys) {
    this.curve = curve;
    this.pubkeys = pubkeys;
  }
}
