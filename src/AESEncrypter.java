import java.security.*;
import javax.crypto.*;

import javax.crypto.spec.IvParameterSpec;
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
  SecureRandom rand;

  public AESEncrypter(Key key) {
    Security.addProvider(new BouncyCastleProvider());
    rand = new SecureRandom();
    this.AESkey = key;
    try {
      AESEncryptCipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public EncryptedMessage encrypt(byte[] toEncrypt) {
    byte[] bytesToEncrypt = toEncrypt;
    byte[] encryptedBytes= null;
    EncryptedMessage send = null;

  try {
      IvParameterSpec ivSpec = updateIV();
      AESEncryptCipher.init(Cipher.ENCRYPT_MODE, AESkey, ivSpec);
      encryptedBytes = AESEncryptCipher.doFinal(bytesToEncrypt);
      send = new EncryptedMessage(encryptedBytes, ivSpec);
    } catch (Exception ex){
      ex.printStackTrace();
    }
    return send;
  }

  public EncryptedMessage encrypt(String toEncrypt) {
    byte[] bytesToEncrypt = toEncrypt.getBytes();
    byte[] encryptedBytes= null;
    EncryptedMessage send = null;

  try {
      IvParameterSpec ivSpec = updateIV();
      AESEncryptCipher.init(Cipher.ENCRYPT_MODE, AESkey, ivSpec);
      encryptedBytes = AESEncryptCipher.doFinal(bytesToEncrypt);
      send = new EncryptedMessage(encryptedBytes, ivSpec);
    } catch (Exception ex){
      ex.printStackTrace();
    }
    return send;
  }

  public EncryptedMessage encrypt(int toEncrypt) {
    String stringToEncrypt = Integer.toString(toEncrypt);
    byte[] bytesToEncrypt = stringToEncrypt.getBytes();
    byte[] encryptedBytes= null;
    EncryptedMessage send = null;

  try {
      IvParameterSpec ivSpec = updateIV();
      AESEncryptCipher.init(Cipher.ENCRYPT_MODE, AESkey, ivSpec);
      encryptedBytes = AESEncryptCipher.doFinal(bytesToEncrypt);
      send = new EncryptedMessage(encryptedBytes, ivSpec);
    } catch (Exception ex){
      ex.printStackTrace();
    }
    return send;
  }

  //Generate a 128-bit random IV 
  public IvParameterSpec updateIV() {
    byte[] ivBytes = new byte[16];
    rand.nextBytes(ivBytes);
    IvParameterSpec AESIVSpec = new IvParameterSpec(ivBytes);
    return AESIVSpec;
  }
}
