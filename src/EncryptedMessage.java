import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public class EncryptedMessage {
  String encryptedMessage;
  byte[] nonce;

  public EncryptedMessage(String encryptedMessage, byte[] nonce) {
    this.encryptedMessage = encryptedMessage;
    this.nonce = nonce;
  }
}
