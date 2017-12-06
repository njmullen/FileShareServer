/* Implements the GroupClient Interface */

import java.util.ArrayList;
import java.util.List;
import java.io.ObjectInputStream;
import java.io.*;
import java.util.*;

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import org.bouncycastle.jce.provider.*;
import java.security.spec.*;
import java.security.*;
import org.bouncycastle.jcajce.provider.digest.SHA3.DigestSHA3;
import org.bouncycastle.util.encoders.Hex;

public class GroupClient extends Client implements GroupClientInterface {

	private BigInteger dhKey = null;
	private Key AESKey = null;
	private AESDecrypter aes = null;
	private String startNonce = null;
	private PublicKey groupKey = null;
	private byte[] tokenBytes = null;
	private byte[] signBytes = null;
	private EncryptedToken tokenObj = null;
	private EncryptedMessage encryptedVal = null;
	private int incrementVal = 0;
	private ArrayList<GroupKeyList> groupKeys = new ArrayList<GroupKeyList>();


	public PublicKey getPublicKey(){
		Envelope message = null;
		Envelope response = null;
		PublicKey publicKey;

		try{
			message = new Envelope("GETPUBLICKEY");
			output.writeObject(message);

			response = (Envelope)input.readObject();
			if(response.getMessage().equals("KEY")){
				publicKey = (PublicKey)response.getObjContents().get(0);
				groupKey = publicKey;
				return publicKey;
			}
		} catch(Exception ex){
			ex.printStackTrace();
		}

		return null;
	}

	public EncryptedMessage increment(){
		incrementVal++;
		AESEncrypter encr = new AESEncrypter(AESKey);
		EncryptedMessage incrementEncrypted = encr.encrypt(incrementVal);
		return incrementEncrypted;
	}

	public boolean checkIncrement(EncryptedMessage incrementEnc){
		AESDecrypter aesDecr = new AESDecrypter(AESKey);
		int incrementSent = aesDecr.decryptInt(incrementEnc);
		incrementVal++;

		if(incrementVal != incrementSent){
			return false;
		} else{
			return true;
		}
	}

	public boolean checkPassword(EncryptedMessage usernameEnc, EncryptedMessage passwordEnc){
		Envelope message = null;
		Envelope response = null;

		//Send encrypted passwords
		try{
			message = new Envelope("CHECKPWD");
			message.addObject(usernameEnc);
			message.addObject(passwordEnc);

			//Add increment value
			EncryptedMessage increment = increment();
			message.addObject(increment);

			output.writeObject(message);

			response = (Envelope)input.readObject();
			//Check increment value
			EncryptedMessage incrementIn = (EncryptedMessage)response.getObjContents().get(0);
			if(!checkIncrement(incrementIn)){
				System.out.println("Client Replay detected");
				System.exit(0);
			}
			if(response.getMessage().equals("OK")){
				return true;
			} else {
				return false;
			}
		} catch(Exception ex){
			ex.printStackTrace();
		}

		return false;
	}

	public void setAESKey(Key AESKeys){
		this.AESKey = AESKeys;
		//Decrypt the increment value
		AESDecrypter valDecr = new AESDecrypter(AESKey);
		incrementVal = valDecr.decryptInt(encryptedVal);
	}

	public EncryptedToken getToken(String username, String fileServer, int filePort){
	 	try{
	 		Envelope message = null;
	 		Envelope response = null;
	 		Security.addProvider(new BouncyCastleProvider());

	 		message = new Envelope("GET");
	 		//Encrypt the username and send it
	 		AESEncrypter usernameEncrypter = new AESEncrypter(AESKey);
	 		EncryptedMessage usernameToSend = usernameEncrypter.encrypt(username);

	 		AESEncrypter fileServerEncrypter = new AESEncrypter(AESKey);
	 		EncryptedMessage fileServerToSend = fileServerEncrypter.encrypt(fileServer);

	 		String filePortString = Integer.toString(filePort);
	 		AESEncrypter filePortEncrypter = new AESEncrypter(AESKey);
	 		EncryptedMessage filePortToSend = filePortEncrypter.encrypt(filePortString);

	 		message.addObject(usernameToSend);
	 		message.addObject(fileServerToSend);
	 		message.addObject(filePortToSend);

	 		//Add increment value
			EncryptedMessage increment = increment();
			message.addObject(increment);

	 		output.writeObject(message);

	 		//Get back the token and signature
	 		response = (Envelope)input.readObject();

	 		//Check increment value
			EncryptedMessage incrementIn = (EncryptedMessage)response.getObjContents().get(2);
			if(!checkIncrement(incrementIn)){
				System.out.println("Client Replay detected");
				System.exit(0);
			}
	 		if(response.getMessage().equals("OK")){

	 			//Decrypt the token and signature
	 			tokenObj = (EncryptedToken)response.getObjContents().get(0);
	 			EncryptedMessage tokenIn = tokenObj.getToken();
				EncryptedMessage signIn = tokenObj.getSignature();

	 			AESDecrypter tokenDecr = new AESDecrypter(AESKey);
	 			AESDecrypter signDecr = new AESDecrypter(AESKey);

	 			tokenBytes = tokenDecr.decryptBytes(tokenIn);
	 			signBytes = signDecr.decryptBytes(signIn);

	 			Signature signature = Signature.getInstance("RSA");
	 			signature.initVerify(groupKey);
	 			signature.update(tokenBytes);
				if (!signature.verify(signBytes)){
					System.out.println("ERROR: Message tampered with, token signature does not match. Exiting....");
					System.exit(0);
				}

	 			//Decrypt the list of group keys
	 			ArrayList<EncryptedGroupKeyList> encList = (ArrayList<EncryptedGroupKeyList>)response.getObjContents().get(1);


	 			groupKeys = new ArrayList<GroupKeyList>();
	 			for(int i = 0; i < encList.size(); i++){
	 				groupKeys.add(encList.get(i).getDecryptedList(AESKey));
	 			}
				// System.out.println("Enclist from groupthead "+encList.size());
				//TROUBLESHOOTING
				// System.out.println("GroupKeySize in client "+groupKeys.size());
				// for( GroupKey k : groupKeys ) {
				// 	System.out.println(k.getName());
				// }
				return tokenObj;

	 		}

	 	} catch(Exception ex){
	 		ex.printStackTrace();
	 	}
	 	return null;
	 }

	 //Diffie-Hellman exchange to create shared AES session key
	 public BigInteger performDiffie(BigInteger p, BigInteger g, BigInteger C){
	 	try{
	 		Envelope message = null, response = null;
	 		message = new Envelope("DH");
		 	message.addObject(p);
		 	message.addObject(g);
		 	message.addObject(C);

		 	output.writeObject(message);

			response = (Envelope)input.readObject();
			if(response.getMessage().equals("OK")){
				//Gets the S and verifies its signature
				BigInteger S = (BigInteger)response.getObjContents().get(0);
				byte[] sSigned = (byte[])response.getObjContents().get(1);

				Signature dhSig = Signature.getInstance("RSA");
				dhSig.initVerify(groupKey);
				dhSig.update(S.toByteArray());
				if(!dhSig.verify(sSigned)){
					System.out.println("Unable to verify DH signature");
					System.exit(0);
				}

				encryptedVal = (EncryptedMessage)response.getObjContents().get(2);
				return S;
			}
			return null;


	 	} catch (Exception ex){
	 		ex.printStackTrace();
	 	}

	 	return null;
	 }

	 public boolean createUser(String username, String password, EncryptedToken token)
	 {
		 try
			{
				//Generate salt
				SecureRandom rand = new SecureRandom();
				byte[] salt = new byte[16];
				rand.nextBytes(salt);

				//Add salt to password
				byte[] temp = password.getBytes("UTF-8");
				byte[] saltedPassword = new byte[salt.length + temp.length];
				for(int i = 0; i < saltedPassword.length; i++){
					if(i < salt.length){
						saltedPassword[i] = salt[i];
					}
					else{
						saltedPassword[i] = temp[i - salt.length];
					}
				}

				//Hash salted password
				Envelope message = null, response = null;
				byte[] passwordHash = null;
				try {
					DigestSHA3 md = new DigestSHA3(256);
	  				md.update(saltedPassword);
	  				passwordHash = md.digest();
				} catch(Exception ex) {
					ex.printStackTrace();
				}
				//Tell the server to create a user
				message = new Envelope("CUSER");

				if(!verifyToken(token)){
					System.out.println("Token error");
					System.exit(0);
				}


				AESEncrypter usernameEnc = new AESEncrypter(AESKey);
				AESEncrypter passwordEnc = new AESEncrypter(AESKey);
				AESEncrypter saltEnc = new AESEncrypter(AESKey);

				EncryptedMessage usernameEncrypted = usernameEnc.encrypt(username);
				EncryptedMessage passwordEncrypted = passwordEnc.encrypt(passwordHash);
				EncryptedMessage saltEncrypted = saltEnc.encrypt(salt);

				EncryptedMessage tokenIn = token.getToken();
				EncryptedMessage signIn = token.getSignature();

				message.addObject(usernameEncrypted); //Add user name string
				message.addObject(passwordEncrypted);
				message.addObject(saltEncrypted);
				message.addObject(tokenIn); //Add the requester's token
				message.addObject(signIn);

				//Add increment value
				EncryptedMessage increment = increment();
				message.addObject(increment);

				output.writeObject(message);

				response = (Envelope)input.readObject();

				//Check increment value
				EncryptedMessage incrementIn = (EncryptedMessage)response.getObjContents().get(0);
				if(!checkIncrement(incrementIn)){
					System.out.println("Client Replay detected");
					System.exit(0);
				}
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}

				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

	 public boolean deleteUser(String username, EncryptedToken token)
	 {
		 try
			{
				Envelope message = null, response = null;

				//Tell the server to delete a user
				message = new Envelope("DUSER");

				if(!verifyToken(token)){
					System.out.println("Token error");
					System.exit(0);
				}

				AESEncrypter usernameEnc = new AESEncrypter(AESKey);
				EncryptedMessage usernameEncrypted = usernameEnc.encrypt(username);

				EncryptedMessage tokenIn = token.getToken();
				EncryptedMessage signIn = token.getSignature();

				message.addObject(usernameEncrypted); //Add user name
				message.addObject(tokenIn);  //Add requester's token
				message.addObject(signIn);

				//Add increment value
				EncryptedMessage increment = increment();
				message.addObject(increment);

				output.writeObject(message);

				response = (Envelope)input.readObject();

				//Check increment value
				EncryptedMessage incrementIn = (EncryptedMessage)response.getObjContents().get(0);
				if(!checkIncrement(incrementIn)){
					System.out.println("Client Replay detected");
					System.exit(0);
				}

				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}

				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

	 public boolean createGroup(String groupname, EncryptedToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to create a group
				message = new Envelope("CGROUP");

				if(!verifyToken(token)){
					System.out.println("Token error");
					System.exit(0);
				}

				AESEncrypter groupEnc = new AESEncrypter(AESKey);
				EncryptedMessage groupEncrypted = groupEnc.encrypt(groupname);

				EncryptedMessage tokenIn = token.getToken();
				EncryptedMessage signIn = token.getSignature();

				message.addObject(groupEncrypted); //Add the group name string
				message.addObject(tokenIn); //Add the requester's token
				message.addObject(signIn);

				//Add increment value
				EncryptedMessage increment = increment();
				message.addObject(increment);

				output.writeObject(message);

				response = (Envelope)input.readObject();

				//If server indicates success, return true
				//Check increment value
				EncryptedMessage incrementIn = (EncryptedMessage)response.getObjContents().get(0);
				if(!checkIncrement(incrementIn)){
					System.out.println("Client Replay detected");
					System.exit(0);
				}
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

	 public boolean deleteGroup(String groupname, EncryptedToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to delete a group
				message = new Envelope("DGROUP");

				if(!verifyToken(token)){
					System.out.println("Token error");
					System.exit(0);
				}

				AESEncrypter groupEnc = new AESEncrypter(AESKey);
				EncryptedMessage groupEncrypted = groupEnc.encrypt(groupname);

				EncryptedMessage tokenIn = token.getToken();
				EncryptedMessage signIn = token.getSignature();

				message.addObject(groupEncrypted); //Add the group name string
				message.addObject(tokenIn); //Add the requester's token
				message.addObject(signIn);

				//Add increment value
				EncryptedMessage increment = increment();
				message.addObject(increment);

				output.writeObject(message);

				response = (Envelope)input.readObject();
				//Check increment value
				EncryptedMessage incrementIn = (EncryptedMessage)response.getObjContents().get(0);
				if(!checkIncrement(incrementIn)){
					System.out.println("Client Replay detected");
					System.exit(0);
				}
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}

				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

	 @SuppressWarnings("unchecked")
	public List<String> listMembers(String group, EncryptedToken token)
	 {
		 try
		 {
			 Envelope message = null, response = null;
			 //Tell the server to return the member list
			 message = new Envelope("LMEMBERS");

			 if(!verifyToken(token)){
					System.out.println("Token error");
					System.exit(0);
			}

			 AESEncrypter groupEnc = new AESEncrypter(AESKey);
			 EncryptedMessage groupEncrypted = groupEnc.encrypt(group);

			 EncryptedMessage tokenIn = token.getToken();
			 EncryptedMessage signIn = token.getSignature();

			 message.addObject(groupEncrypted); //Add the group name string
			 message.addObject(tokenIn); //Add the requester's token
			 message.addObject(signIn);

			 //Add increment value
			 EncryptedMessage increment = increment();
			 message.addObject(increment);

			 output.writeObject(message);

			 response = (Envelope)input.readObject();

			 //If server indicates success, return the member list
			 if(response.getMessage().equals("OK"))
			 {
			 	int size = (int)response.getObjContents().get(0);
			 	List<String> memberList = new ArrayList<String>();
			 	for(int i = 1; i < size + 1; i++){
			 		EncryptedMessage encList = (EncryptedMessage)response.getObjContents().get(i);
			 		AESDecrypter listDecr = new AESDecrypter(AESKey);
			 		String thisMember = listDecr.decrypt(encList);
			 		memberList.add(thisMember);
			 	}
			 	//Check increment value
				EncryptedMessage incrementIn = (EncryptedMessage)response.getObjContents().get(memberList.size() + 1);
				if(!checkIncrement(incrementIn)){
					System.out.println("Client Replay detected");
					System.exit(0);
				}
			 	return memberList;
			 } else {
			 	//Check increment value
				EncryptedMessage incrementIn = (EncryptedMessage)response.getObjContents().get(0);
				if(!checkIncrement(incrementIn)){
					System.out.println("Client Replay detected");
					System.exit(0);
				}
			 }

			 return null;

		 }
		 catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return null;
			}
	 }

	 public boolean addUserToGroup(String username, String groupname, EncryptedToken token)
	 {
		 try
			{
				if(!verifyToken(token)){
					System.out.println("Token error");
					System.exit(0);
				}

				AESEncrypter usernameEnc = new AESEncrypter(AESKey);
				EncryptedMessage usernameEncrypted = usernameEnc.encrypt(username);

				AESEncrypter groupEnc = new AESEncrypter(AESKey);
				EncryptedMessage groupEncrypted = groupEnc.encrypt(groupname);

				EncryptedMessage tokenIn = token.getToken();
				EncryptedMessage signIn = token.getSignature();

				Envelope message = null, response = null;
				//Tell the server to add a user to the group
				message = new Envelope("AUSERTOGROUP");
				message.addObject(usernameEncrypted); //Add user name string
				message.addObject(groupEncrypted); //Add group name string
				message.addObject(tokenIn); //Add requester's token
				message.addObject(signIn); //Add requester's token

				//Add increment value
				EncryptedMessage increment = increment();
				message.addObject(increment);

				output.writeObject(message);

				response = (Envelope)input.readObject();
				//Check increment value
				EncryptedMessage incrementIn = (EncryptedMessage)response.getObjContents().get(0);
				if(!checkIncrement(incrementIn)){
					System.out.println("Client Replay detected");
					System.exit(0);
				}
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}

				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

	 public boolean deleteUserFromGroup(String username, String groupname, EncryptedToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to remove a user from the group
				message = new Envelope("RUSERFROMGROUP");

				if(!verifyToken(token)){
					System.out.println("Token error");
					System.exit(0);
				}

				AESEncrypter groupEnc = new AESEncrypter(AESKey);
				AESEncrypter userEnc = new AESEncrypter(AESKey);
				EncryptedMessage groupEncrypted = groupEnc.encrypt(groupname);
				EncryptedMessage userEncrypted = userEnc.encrypt(username);

				EncryptedMessage tokenIn = token.getToken();
				EncryptedMessage signIn = token.getSignature();

				message.addObject(userEncrypted); //Add user name string
				message.addObject(groupEncrypted); //Add group name string
				message.addObject(tokenIn); //Add requester's token
				message.addObject(signIn);

				//Add increment value
				EncryptedMessage increment = increment();
				message.addObject(increment);

				output.writeObject(message);

				response = (Envelope)input.readObject();
				//Check increment value
				EncryptedMessage incrementIn = (EncryptedMessage)response.getObjContents().get(0);
				if(!checkIncrement(incrementIn)){
					System.out.println("Client Replay detected");
					System.exit(0);
				}
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}

				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

	 public boolean verifyToken(EncryptedToken tokenIn){
	 	EncryptedMessage token = tokenIn.token;
	 	EncryptedMessage signature = tokenIn.signature;

	 	AESDecrypter tokenDecr = new AESDecrypter(AESKey);
	 	byte[] tokenPlain = tokenDecr.decryptBytes(token);
	 	if(!Arrays.equals(tokenPlain, tokenBytes)){
	 		return false;
	 	} else {
	 		return true;
	 	}
	 }

	public ArrayList<GroupKeyList> getGroupKeys(){
		return groupKeys;
	}
}
