import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public class EncryptedMessage implements java.io.Serializable {
  byte[] encryptedMessage;
  IvParameterSpec ivSpec;
  private static final long serialVersionUID = 7600343803563417992L;

  public EncryptedMessage(byte[] encryptedMessage, IvParameterSpec ivSpec) {
    this.encryptedMessage = encryptedMessage;
    this.ivSpec = ivSpec;
  }
}
