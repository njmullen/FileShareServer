import javax.crypto.spec.IvParameterSpec;

public class EncryptedToken{
	EncryptedMessage encToken;
	EncryptedMessage encSigToken;

	public EncryptedToken(EncryptedMessage plainText, EncryptedMessage signed){
		encToken = plainText;
		encSigToken = signed;
	}
}