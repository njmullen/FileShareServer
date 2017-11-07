import java.security.*;
import javax.crypto.*;

import javax.crypto.spec.IVParameterSpec;
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

public class AESDecrypter {
  Key AESkey = null;
  Cipher AESDecryptCipher = null;
  BigInteger currNonce = null;

  public AESDecrypter(Key key) {
    Security.addProvider(new BouncyCastleProvider());
    this.AESkey = key;
    //currNonce = new BigInteger(nonce, 2);
    try {
      AESDecryptCipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public String decrypt(EncryptedMessage sent) {
       byte[] decryptedText = null;
       byte[] encryptedBytes = sent.encryptedMessage.getBytes();

    try {
        IVParameterSpec GCMSpec = sent.passedIV;
        AESDecryptCipher.init(Cipher.DECRYPT_MODE, AESkey, GCMSpec);
        decryptedText = AESDecryptCipher.doFinal(encryptedBytes);
      } catch (Exception ex){
        ex.printStackTrace();
      }
      return new String(decryptedText);
    }

  public IVParameterSpec updateIV() {
    byte[] nonce = new byte[8];
    return new IVParameterSpec(128, nonce);
  }
}
