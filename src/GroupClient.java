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

	public byte[] sendRandomChallenge(byte[] challenge){
		//Decrypt the random challenge with private key and return it
		Security.addProvider(new BouncyCastleProvider());
		PrivateKey privateKey = null;
		byte[] decryptedChallenge = null;
		try {
			File privateKeyFile = new File("groupPrivateKey");
			FileInputStream input = new FileInputStream(privateKeyFile);
			byte[] privateKeyBytes = new byte[input.available()];
			input.read(privateKeyBytes);
			input.close();

			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			privateKey = keyFactory.generatePrivate(privateKeySpec);

			Cipher RSACipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
            RSACipher.init(Cipher.DECRYPT_MODE, privateKey);
            //Decrypt the string using the Cipher
            decryptedChallenge = RSACipher.doFinal(challenge);
		} catch (Exception ex){
			ex.printStackTrace();
		}

		return decryptedChallenge;
	}

	public PublicKey getPublicKey(){
		byte[] publicKeyBytes = null;
		PublicKey publicKey = null;

		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			File publicKeyFile = new File("groupPublicKey");
			FileInputStream input = new FileInputStream(publicKeyFile);
			publicKeyBytes = new byte[input.available()];
			input.read(publicKeyBytes);
			input.close();

			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
			publicKey = keyFactory.generatePublic(publicKeySpec);
		} catch (Exception ex){
			ex.printStackTrace();
		}

		return publicKey;
	}

	public boolean checkPassword(String usernameEnc, String passwordEnc){
		aes = new AESDecrypter(AESKey, startNonce);
		String username = aes.decrypt(usernameEnc);
		String password = aes.decrypt(passwordEnc);
		Envelope message = null;
		Envelope response = null;
		try {
			message = new Envelope("CHECKPWD");
			byte[] passwordHash = null;
			try {
				DigestSHA3 md = new DigestSHA3(256);
  				md.update(password.getBytes("UTF-8"));
  				passwordHash = md.digest();
			} catch(Exception ex) {
				ex.printStackTrace();
			}
			message.addObject(username);
			message.addObject(passwordHash);
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

	 public UserToken getToken(String username)
	 {
		try
		{
			UserToken token = null;
			Envelope message = null, response = null;

			//Tell the server to return a token.
			message = new Envelope("GET");
			message.addObject(username); //Add user name string
			output.writeObject(message);

			//Get the response from the server
			response = (Envelope)input.readObject();

			//Successful response
			if(response.getMessage().equals("OK"))
			{
				//If there is a token in the Envelope, return it
				ArrayList<Object> temp = null;
				temp = response.getObjContents();

				if(temp.size() == 1)
				{
					//Set security provider and read private key from file
					Security.addProvider(new BouncyCastleProvider());
					token = (UserToken)temp.get(0);

					try {
						File privateKeyFile = new File("groupPrivateKey");
						FileInputStream input = new FileInputStream(privateKeyFile);
						byte[] privateKeyBytes = new byte[input.available()];
						input.read(privateKeyBytes);
						input.close();

						PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
						KeyFactory keyFactory = KeyFactory.getInstance("RSA");
						PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

						byte[] tokenString = token.getTokenString();

						Signature signature = Signature.getInstance("RSA");
						signature.initSign(privateKey);
	            		signature.update(tokenString);
	            		byte[] signatureBytes = signature.sign();

	            		//Verifies token signature
	            		File publicKeyFile = new File("groupPublicKey");
	            		FileInputStream input2 = new FileInputStream(publicKeyFile);
	            		byte[] publicKeyBytes = new byte[input2.available()];
	            		input2.read(publicKeyBytes);
	            		input2.close();

	            		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
						PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

	            		signature.initVerify(publicKey);
	            		signature.update(tokenString);
	            		boolean signaturePass = signature.verify(signatureBytes);
	            		System.out.println("Signature " + signaturePass);
					} catch(Exception ex){
						ex.printStackTrace();
					}

					return token;
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

	 //Diffie-Hellman exchange to create shared AES session key
	 public BigInteger performDiffie(BigInteger p, BigInteger g, BigInteger C){
	 	Random random = new Random();
	 	BigInteger s = new BigInteger(1024, random);
	 	BigInteger S = g.modPow(s, p);
	 	dhKey = C.modPow(s, p);

	 	byte[] dhKeyBytes = dhKey.toByteArray();
	 	byte[] shortBytes = new byte[16];

	 	//System.out.println("GS-Side DH Key: "+ dhKey.toString());

	 	for(int i = 0; i < 16; i++){
	 		shortBytes[i] = dhKeyBytes[i];
	 	}

	 	try{
	 		AESKey = new SecretKeySpec(shortBytes, "AES");
	 	}
	 	catch(Exception ex){
	 		ex.printStackTrace();
	 	}

	 	return S;
	 }

	 public void setNonce(String nonce) {
		 startNonce = nonce;
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
				message.addObject(username); //Add user name string
				message.addObject(passwordHash);
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
