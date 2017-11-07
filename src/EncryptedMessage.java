import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public class EncryptedMessage {
  byte[] encryptedMessage;
  IvParameterSpec ivSpec;

  public EncryptedMessage(byte[] encryptedMessage, IvParameterSpec ivSpec) {
    this.encryptedMessage = encryptedMessage;
    this.ivSpec = ivSpec;
  }
}
