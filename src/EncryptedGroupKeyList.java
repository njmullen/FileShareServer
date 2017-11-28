
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.ArrayList;

public class EncryptedGroupKeyList implements java.io.Serializable{
	EncryptedMessage groupName;
	ArrayList<EncryptedMessage> groupKeys;
	EncryptedMessage mostRecent;

	public EncryptedGroupKeyList(EncryptedMessage name){
		groupName = name;
		groupKeys = new ArrayList<EncryptedMessage>();
		mostRecent = null;
	}

	public EncryptedGroupKeyList(EncryptedMessage name, EncryptedMessage key){
		groupName = name;
		groupKeys = new ArrayList<EncryptedMessage>();
		groupKeys.add(key);
		mostRecent = groupKeys.get(0);
	}

	public GroupKeyList getDecryptedList(Key AESKey){
		AESDecrypter nameDecrypter = new AESDecrypter(AESKey);
		String decName = nameDecrypter.decrypt(groupName);
		GroupKeyList keyList = new GroupKeyList(decName);

		for(int i = 0; i < groupKeys.size(); i++){
			AESDecrypter keyDecrypter = new AESDecrypter(AESKey);
			byte[] keyBytes = keyDecrypter.decryptBytes(groupKeys.get(i));

			byte[] decodedKey = Base64.getDecoder().decode(keyBytes);
			SecretKey key = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
			keyList.addKey(key);
		}	

		return keyList;
	}

	public SecretKey getDecryptedKey(Key AESKey){
		AESDecrypter keyDecrypter = new AESDecrypter(AESKey);
		byte[] keyBytes = keyDecrypter.decryptBytes(mostRecent);
		byte[] decodedKey = Base64.getDecoder().decode(keyBytes);
		SecretKey key = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
	
		return key;
	}

	public void addKey(EncryptedMessage key){
		groupKeys.add(key);
		mostRecent = key;
	}

	public EncryptedMessage getName(){
		return groupName;
	}

	public EncryptedMessage getKey(){
		return mostRecent;
	}

	public ArrayList<EncryptedMessage> getKeys(){
		return groupKeys;
	}
}