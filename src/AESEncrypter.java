import java.security.*;
import javax.crypto.*;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.jce.provider.*;
import java.security.spec.*;
import java.security.*;
import org.bouncycastle.jcajce.provider.digest.SHA3.DigestSHA3;
import org.bouncycastle.util.encoders.Hex;

import java.util.Arrays;

public class AESEncrypter {
  Key AESkey = null;
  Cipher AESEncryptCipher = null;
  BigInteger currNonce = null;
  SecureRandom rand;

  public AESEncrypter(Key key, String nonce) {
    Security.addProvider(new BouncyCastleProvider());
    rand = new SecureRandom();
    this.AESkey = key;
    currNonce = new BigInteger(nonce, 2);
    try {
      AESEncryptCipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public EncryptedMessage encrypt(String toEncrypt) {
    byte[] bytesToEncrypt = toEncrypt.getBytes();
    byte[] encryptedBytes= null;
    EncryptedMessage send = null;

  try {
      GCMParameterSpec GCMSpec = updateIV();
      AESEncryptCipher.init(Cipher.ENCRYPT_MODE, AESkey, GCMSpec);
      encryptedBytes = AESEncryptCipher.doFinal(bytesToEncrypt);
      send = new EncryptedMessage(new String(encryptedBytes), GCMSpec);
    } catch (Exception ex){
      ex.printStackTrace();
    }
    return send;
  }

  public GCMParameterSpec updateIV() {
    byte[] nonce = new byte[8];
    rand.nextBytes(nonce);
    return new GCMParameterSpec(128, nonce);
  }
}
