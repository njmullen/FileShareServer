import javax.crypto.spec.GCMParameterSpec;


public class EncryptedMessage {
  String encryptedMessage;
  GCMParameterSpec passedIV;

  public EncryptedMessage(String encryptedMessage, GCMParameterSpec passedIV) {
    this.encryptedMessage = encryptedMessage;
    this.passedIV = passedIV;
  }
}
