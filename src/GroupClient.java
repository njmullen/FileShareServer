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
	private EncryptedMessage tokenIn = null;
	private EncryptedMessage signIn = null;

	public boolean sendRandomChallenge(byte[] challenge, byte[] challengeOriginal){
		Envelope message = null;
		Envelope response = null;
		byte[] decryptedChallenge = null;

		try{
			message = new Envelope("RANDOM");
			message.addObject(challenge);
			output.writeObject(message);

			response = (Envelope)input.readObject();
			if(response.getMessage().equals("OK")){
				decryptedChallenge = (byte[])response.getObjContents().get(0);
				if(Arrays.equals(decryptedChallenge, challengeOriginal)){
					return true;
				} else {
					return false;
				}
			} else {
				return false;
			}
		} catch (Exception ex){
			ex.printStackTrace();
		}

		return false;
	}

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

	public boolean checkPassword(String usernameEnc, String passwordEnc){
		System.out.println("shouldn't be in here");
		return false;

	}

	public boolean checkPassword(EncryptedMessage usernameEnc, EncryptedMessage passwordEnc){
		Envelope message = null;
		Envelope response = null;

		//Send encrypted passwords
		try{
			message = new Envelope("CHECKPWD");
			message.addObject(usernameEnc);
			message.addObject(passwordEnc);
			output.writeObject(message);

			response = (Envelope)input.readObject();
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
	}

	 public UserToken getToken(String username){
	 	try{
	 		Envelope message = null;
	 		Envelope response = null;
	 		Security.addProvider(new BouncyCastleProvider());

	 		message = new Envelope("GET");
	 		//Encrypt the username and send it
	 		AESEncrypter encrypter = new AESEncrypter(AESKey);
	 		EncryptedMessage usernameToSend = encrypter.encrypt(username);
	 		message.addObject(usernameToSend);
	 		output.writeObject(message);

	 		//Get back the token and signature
	 		response = (Envelope)input.readObject();
	 		if(response.getMessage().equals("OK")){
	 			tokenIn = (EncryptedMessage)response.getObjContents().get(0);
	 			signIn = (EncryptedMessage)response.getObjContents().get(1);

	 			AESDecrypter tokenDecr = new AESDecrypter(AESKey);
	 			AESDecrypter signDecr = new AESDecrypter(AESKey);

	 			tokenBytes = tokenDecr.decryptBytes(tokenIn);
	 			signBytes = signDecr.decryptBytes(signIn);

	 			Signature signature = Signature.getInstance("RSA");
	 			signature.initVerify(groupKey);
	 			signature.update(tokenBytes);
	 			if (signature.verify(signBytes)){
	 				Token token = new Token(tokenBytes);
	 				return token;
	 			} else {
	 				System.exit(0);
	 			}
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
				BigInteger S = (BigInteger)response.getObjContents().get(0);
				return S;
			}
			return null;


	 	} catch (Exception ex){
	 		ex.printStackTrace();
	 	}
	 	
	 	return null;
	 }

	 public boolean createUser(String username, String password, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				byte[] passwordHash = null;
				try {
					DigestSHA3 md = new DigestSHA3(256);
	  				md.update(password.getBytes("UTF-8"));
	  				passwordHash = md.digest();
				} catch(Exception ex) {
					ex.printStackTrace();
				}
				//Tell the server to create a user
				message = new Envelope("CUSER");

				if(!Arrays.equals(token.getTokenString(), tokenBytes)){
					System.out.println("Token error");
					System.exit(0);
				}



				message.addObject(username); //Add user name string
				message.addObject(passwordHash);
				message.addObject(tokenIn); //Add the requester's token
				message.addObject(signIn);
				output.writeObject(message);

				response = (Envelope)input.readObject();

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

	 public boolean deleteUser(String username, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;

				//Tell the server to delete a user
				message = new Envelope("DUSER");
				message.addObject(username); //Add user name
				message.addObject(token);  //Add requester's token
				output.writeObject(message);

				response = (Envelope)input.readObject();

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

	 public boolean createGroup(String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to create a group
				message = new Envelope("CGROUP");
				message.addObject(groupname); //Add the group name string
				message.addObject(token); //Add the requester's token
				output.writeObject(message);

				response = (Envelope)input.readObject();

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

	 public boolean deleteGroup(String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to delete a group
				message = new Envelope("DGROUP");
				message.addObject(groupname); //Add group name string
				message.addObject(token); //Add requester's token
				output.writeObject(message);

				response = (Envelope)input.readObject();
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
	public List<String> listMembers(String group, UserToken token)
	 {
		 try
		 {
			 Envelope message = null, response = null;
			 //Tell the server to return the member list
			 message = new Envelope("LMEMBERS");
			 message.addObject(group); //Add group name string
			 message.addObject(token); //Add requester's token
			 output.writeObject(message);

			 response = (Envelope)input.readObject();

			 //If server indicates success, return the member list
			 if(response.getMessage().equals("OK"))
			 {
				return (List<String>)response.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
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

	 public boolean addUserToGroup(String username, String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to add a user to the group
				message = new Envelope("AUSERTOGROUP");
				message.addObject(username); //Add user name string
				message.addObject(groupname); //Add group name string
				message.addObject(token); //Add requester's token
				output.writeObject(message);

				response = (Envelope)input.readObject();
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

	 public boolean deleteUserFromGroup(String username, String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to remove a user from the group
				message = new Envelope("RUSERFROMGROUP");
				message.addObject(username); //Add user name string
				message.addObject(groupname); //Add group name string
				message.addObject(token); //Add requester's token
				output.writeObject(message);

				response = (Envelope)input.readObject();
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

}
