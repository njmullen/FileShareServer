
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class EncryptedGroupKey implements java.io.Serializable{
	EncryptedMessage groupName;
	EncryptedMessage groupKey;

	public EncryptedGroupKey(EncryptedMessage name, EncryptedMessage key){
		groupName = name;
		groupKey = key;
	}

	public GroupKey getDecrypted(Key AESKey){
		AESDecrypter nameDecrypter = new AESDecrypter(AESKey);
		AESDecrypter keyDecrypter = new AESDecrypter(AESKey);
		String decName = nameDecrypter.decrypt(groupName);
		byte[] keyBytes = keyDecrypter.decryptBytes(groupKey);

		byte[] decodedKey = Base64.getDecoder().decode(keyBytes);
		SecretKey key = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

		return new GroupKey(decName, key);
	}

	public EncryptedMessage getName(){
		return groupName;
	}

	public EncryptedMessage getKey(){
		return groupKey;
	}
}