package c.c;

import org.bouncycastle.crypto.digests.KeccakDigest;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

class RingCtTest {

  private ECNamedCurveParameterSpec curve;

  private RingCt ringCt;

  private KeccakDigest keccak = new KeccakDigest();

  // private key
  private BigInteger x = new BigInteger("2de7089f15096ae7d45d6e85fe00669da2a91610097c932a757850f1e65102e", 16);

  // ring members
  private List<ECPoint> ringMembers;

  // secret index
  int j = 1;


  @BeforeEach
  void init() {
    curve = ECNamedCurveTable.getParameterSpec("curve25519");
    ringCt = new RingCt(
        curve,
        Collections.emptyList());
    ringMembers = new ArrayList<>(3);
    ringMembers.add(curve.getCurve().decodePoint(new BigInteger(
        "4346f4b8d3e395a5a0c81c2241dd3c1df68233eacd9ad7b2ceaea72d81d7b4769216e49dc4140a82ff7559400c2ee1a35022f0161ea7032c4eb6c9d3a12e083cf", 16)
        .toByteArray()));
    ringMembers.add(myPubKey());
    ringMembers.add(curve.getCurve().decodePoint(new BigInteger(
        "42852e1dcc22765a75474aaa5614f2537d6dacdc96b406d2bc1b0bc846dd2ba3d7ddb053f77508282fde3c78c0ca339dafe6659a77e3c4fd878b68cf170ccce68", 16)
        .toByteArray()));
  }

  @Test
  void rctTest() {
    ECPoint I = curveHash(myPubKey()).multiply(x);
    System.out.println(I.normalize());
  }

  private ECPoint curveHash(ECPoint point) {
    byte[] bytes = point.getEncoded(false);
    keccak.update(bytes, 0, bytes.length);
    int i = curve.getN().bitLength();
    while (i % 8 != 0) {
      ++i;
    }
    byte[] out = new byte[i];
    keccak.doFinal(out, 0);
    return curve.getG().multiply(fromBytes(out));
  }

  private ECPoint pubKey(BigInteger x) {
    return curve.getG().multiply(x);
  }

  private ECPoint myPubKey() {
    return pubKey(x);
  }

  BigInteger fromBytes(byte[] bytes) {
    BigInteger n = curve.getN();
    return new BigInteger(bytes, 0, n.bitLength());
  }
}