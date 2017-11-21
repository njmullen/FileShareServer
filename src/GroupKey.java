
import javax.crypto.*;
import java.security.*;
import java.util.Base64;

public class GroupKey implements java.io.Serializable{
	String name;
	SecretKey key;

	public GroupKey(String groupName, SecretKey groupKey){
		this.name = groupName;
		this.key = groupKey;
	}

	public EncryptedGroupKey getEncrypted(Key AESKey){
		AESEncrypter nameEncrypter = new AESEncrypter(AESKey);
		AESEncrypter keyEncrypter = new AESEncrypter(AESKey);
		EncryptedMessage encName = nameEncrypter.encrypt(name.getBytes());
		EncryptedMessage encKey = keyEncrypter.encrypt(Base64.getEncoder().encode(key.getEncoded()));

		return new EncryptedGroupKey(encName, encKey);
	}

	public String getName(){
		return name;
	}

	public SecretKey getKey(){
		return key;
	}
}