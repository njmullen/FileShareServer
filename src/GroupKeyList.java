
import javax.crypto.*;
import java.security.*;
import java.util.Base64;
import java.util.ArrayList;

public class GroupKeyList implements java.io.Serializable{
	String name;
	ArrayList<SecretKey> keys;
	SecretKey mostRecent;

	public GroupKeyList(String groupName){
		name = groupName;
		keys = new ArrayList<SecretKey>();
		mostRecent = null;
	}

	public GroupKeyList(String groupName, SecretKey groupKey){
		name = groupName;
		keys = new ArrayList<SecretKey>();
		keys.add(groupKey);
		mostRecent = keys.get(0);
	}

	public EncryptedGroupKeyList getEncryptedKey(Key AESKey){
		AESEncrypter nameEncrypter = new AESEncrypter(AESKey);
		AESEncrypter keyEncrypter = new AESEncrypter(AESKey);
		EncryptedMessage encName = nameEncrypter.encrypt(name.getBytes());
		EncryptedMessage encKey = keyEncrypter.encrypt(Base64.getEncoder().encode(mostRecent.getEncoded()));
		return new EncryptedGroupKeyList(encName, encKey);
	}

	public EncryptedGroupKeyList getEncryptedList(Key AESKey){
		AESEncrypter nameEncrypter = new AESEncrypter(AESKey);
		EncryptedMessage encName = nameEncrypter.encrypt(name.getBytes());
		EncryptedGroupKeyList encList = new EncryptedGroupKeyList(encName);
		
		for(int i = 0; i < keys.size(); i++){
			AESEncrypter keyEncrypter = new AESEncrypter(AESKey);
			EncryptedMessage encKey = keyEncrypter.encrypt(Base64.getEncoder().encode(keys.get(i).getEncoded()));
			encList.addKey(encKey);
		}
		return encList;
	}

	public void addKey(SecretKey key){
		keys.add(key);
		mostRecent = key;
	}

	public String getName(){
		return name;
	}

	public SecretKey getEncrypterKey(){
		return mostRecent;
	}

	public ArrayList<SecretKey> getKeys(){
		return keys;
	}
}