package c.c;

import org.bouncycastle.crypto.digests.KeccakDigest;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Collectors;
import java.util.stream.Stream;

class RingCtTest {

  private ECNamedCurveParameterSpec curve;

  private RingCt ringCt;

  // private key
  private BigInteger x = new BigInteger("2de7089f15096ae7d45d6e85fe00669da2a91610097c932a757850f1e65102e", 16);

  private KeyPair myKey = new KeyPair(curve, x);

  private Hash keccak = new Hash(new KeccakDigest(), curve);

  @BeforeEach
  void init() {
    curve = ECNamedCurveTable.getParameterSpec("curve25519");
    List<ECPoint> ringMembers = Stream.of(
        "4346f4b8d3e395a5a0c81c2241dd3c1df68233eacd9ad7b2ceaea72d81d7b4769216e49dc4140a82ff7559400c2ee1a35022f0161ea7032c4eb6c9d3a12e083cf",
        "42852e1dcc22765a75474aaa5614f2537d6dacdc96b406d2bc1b0bc846dd2ba3d7ddb053f77508282fde3c78c0ca339dafe6659a77e3c4fd878b68cf170ccce68")
        .map(s -> new BigInteger(s, 16))
        .map(BigInteger::toByteArray)
        .map(i -> curve.getCurve().decodePoint(i))
        .collect(Collectors.toList());
    ringCt = new RingCt(
        curve.getG(),
        ringMembers,
        myKey,
        keccak);
  }

  @Test
  void test() {

  }

  BigInteger randomNumber() {
    Random rnd = ThreadLocalRandom.current();
    BigInteger n = curve.getN();
    BigInteger r;
    do {
      r = new BigInteger(n.bitLength(), rnd);
    } while (r.compareTo(n) >= 0);
    return r;
  }
}