public class EncryptedToken implements java.io.Serializable{

	EncryptedMessage token;
	EncryptedMessage signature;
	private static final long serialVersionUID = 7600343803563417992L;
	
	public EncryptedToken(EncryptedMessage tokenIn, EncryptedMessage signatureIn){
		this.token = tokenIn;
		this.signature = signatureIn;
	}

	public EncryptedMessage getToken(){
		return token;
	}

	public EncryptedMessage getSignature(){
		return signature;
	}
}