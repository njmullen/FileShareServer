/* This thread does all the work. It communicates with the client through Envelopes.
 *
 */
import java.lang.Thread;
import java.net.Socket;
import java.io.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;
import java.math.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import org.bouncycastle.jce.provider.*;
import java.security.spec.*;
import java.security.*;
import org.bouncycastle.jcajce.provider.digest.SHA3.DigestSHA3;
import org.bouncycastle.util.encoders.Hex;

public class GroupThread extends Thread
{
	private final Socket socket;
	private GroupServer my_gs;
	private BigInteger dhKey = null;
	private Key AESKey = null;
	private PublicKey publicKey;
	private PrivateKey privateKey;

	public GroupThread(Socket _socket, GroupServer _gs)
	{
		socket = _socket;
		my_gs = _gs;
		Security.addProvider(new BouncyCastleProvider());

		//Read in public and private keys
		try{
			File privateKeyFile = new File("groupPrivateKey");
			FileInputStream input = new FileInputStream(privateKeyFile);
			byte[] privateKeyBytes = new byte[input.available()];
			input.read(privateKeyBytes);
			input.close();

			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			privateKey = keyFactory.generatePrivate(privateKeySpec);

			File publicKeyFile = new File("groupPublicKey");
			FileInputStream keyIn = new FileInputStream(publicKeyFile);
			byte[] publicKeyBytes = new byte[keyIn.available()];
			keyIn.read(publicKeyBytes);
			keyIn.close();

			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
			publicKey = keyFactory.generatePublic(publicKeySpec);
		} catch (Exception ex){
			ex.printStackTrace();
		}
		
	}

	public void run()
	{
		boolean proceed = true;

		try
		{
			//Announces connection and opens object streams
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());

			do
			{
				Envelope message = (Envelope)input.readObject();
				System.out.println("Request received: " + message.getMessage());
				Envelope response;

				if(message.getMessage().equals("GET"))//Client wants a token
				{
					EncryptedMessage usernameEnc = (EncryptedMessage)message.getObjContents().get(0); //Get the username
					AESDecrypter aesDecrypter = new AESDecrypter(AESKey);
					String username = aesDecrypter.decrypt(usernameEnc);
					if(username == null)
					{
						response = new Envelope("FAIL");
						response.addObject(null);
						output.writeObject(response);
					}
					else
					{
						UserToken yourToken = createToken(username); //Create a token
						
						String issuer = yourToken.getIssuer();
						String subject = yourToken.getSubject();
						List<String> groupList = yourToken.getGroups();

						List<String> newGroupList = new ArrayList<String>();
						for (int i = 0; i < groupList.size(); i++){
							newGroupList.add(groupList.get(i));
						}

						Token token = new Token(issuer, subject, newGroupList);

						//Respond to the client. On error, the client will receive a null token
						response = new Envelope("OK");

						//Encrypt the token
						byte[] tokenString = token.getTokenString();
						byte[] signedToken = null;
						try{
							Signature signature = Signature.getInstance("RSA");
							signature.initSign(privateKey);
							signature.update(tokenString);
							signedToken = signature.sign();
						} catch (Exception a){
							a.printStackTrace();
						}

						AESEncrypter tokenEncrypter = new AESEncrypter(AESKey);
						AESEncrypter signedTokenEncrypter = new AESEncrypter(AESKey);

						EncryptedMessage tokenToPass = tokenEncrypter.encrypt(tokenString);
						EncryptedMessage signToPass = signedTokenEncrypter.encrypt(signedToken);
						EncryptedToken encryptedToken = new EncryptedToken(tokenToPass, signToPass);

						response.addObject(encryptedToken);
						output.writeObject(response);
					}
				}
				else if(message.getMessage().equals("CUSER")) //Client wants to create a user
				{
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");

						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								EncryptedMessage username = (EncryptedMessage)message.getObjContents().get(0); //Extract the username
								EncryptedMessage password = (EncryptedMessage)message.getObjContents().get(1);
								EncryptedMessage token = (EncryptedMessage)message.getObjContents().get(2); //Extract the token
								EncryptedMessage tokenSignature = (EncryptedMessage)message.getObjContents().get(3);

								if(!verifySignature(token, tokenSignature)){
									System.out.println("Invalid signature");
									System.exit(0);
								}

								AESDecrypter usernameDecr = new AESDecrypter(AESKey);
								AESDecrypter passwordDecr = new AESDecrypter(AESKey);
								AESDecrypter tokenDecr = new AESDecrypter(AESKey);
								String usernamePlain = usernameDecr.decrypt(username);
								byte[] passwordPlain = passwordDecr.decryptBytes(password);
								byte[] tokenPlain = tokenDecr.decryptBytes(token);

								Token yourToken = new Token(tokenPlain);


								if(createUser(usernamePlain, passwordPlain, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}

					output.writeObject(response);
				}
				else if(message.getMessage().equals("DUSER")) //Client wants to delete a user
				{

					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");

						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								EncryptedMessage username = (EncryptedMessage)message.getObjContents().get(0); //Extract the username
								EncryptedMessage tokenIn = (EncryptedMessage)message.getObjContents().get(1); //Extract the token
								EncryptedMessage signIn = (EncryptedMessage)message.getObjContents().get(2); //extract signature

								if(!verifySignature(tokenIn, signIn)){
									System.out.println("Token error");
									System.exit(0);
								}
								AESDecrypter usernameDecr = new AESDecrypter(AESKey);
								AESDecrypter tokenDecr = new AESDecrypter(AESKey);
								String userPlain = usernameDecr.decrypt(username);
								byte[] tokenPlain = tokenDecr.decryptBytes(tokenIn);
								Token yourToken = new Token(tokenPlain);

								if(deleteUser(userPlain, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}

					output.writeObject(response);
				}
				else if(message.getMessage().equals("CGROUP")) //Client wants to create a group
				{
				    if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");

						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String groupName = (String)message.getObjContents().get(0); //Extract the username
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

								if(createGroup(groupName, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}

					output.writeObject(response);
				}
				else if(message.getMessage().equals("DGROUP")) //Client wants to delete a group
				{
				    if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						//TODO: add third check for null
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String groupToDelete = (String)message.getObjContents().get(0); //Extract the username
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

								if(deleteGroup(groupToDelete, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}

					output.writeObject(response);
				}
				else if(message.getMessage().equals("LMEMBERS")) //Client wants a list of members in a group
				{
				    if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");

						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String groupnameToList = (String)message.getObjContents().get(0); //Extract the groupname
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

								List<String> members = listMembers(groupnameToList, yourToken);
								response = new Envelope("OK"); //Success
								response.addObject(members);
								
							}
						}
					}

					output.writeObject(response);
				}
				else if(message.getMessage().equals("AUSERTOGROUP")) //Client wants to add user to a group
				{
				    if(message.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");

						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								if(message.getObjContents().get(2) != null)
								{
									String usernameToAdd = (String)message.getObjContents().get(0); //Extract the username
									String groupnameToAdd = (String)message.getObjContents().get(1); //Extract the groupname
									UserToken yourToken = (UserToken)message.getObjContents().get(2); //Extract the token

									if(addUserToGroup(usernameToAdd, groupnameToAdd, yourToken))
									{
										response = new Envelope("OK"); //Success
									}
								}
							}
						}
					}

					output.writeObject(response);
				}
				else if(message.getMessage().equals("RUSERFROMGROUP")) //Client wants to remove user from a group
				{
				    if(message.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");

						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								if(message.getObjContents().get(2) != null)
								{
									String usernameToDelete = (String)message.getObjContents().get(0); //Extract the username
									String groupnameToDelete = (String)message.getObjContents().get(1); //Extract the groupname
									UserToken yourToken = (UserToken)message.getObjContents().get(2); //Extract the token

									if(deleteUserFromGroup(usernameToDelete, groupnameToDelete, yourToken))
									{
										response = new Envelope("OK"); //Success
									}
								}
							}
						}
					}

					output.writeObject(response);
				}
				else if(message.getMessage().equals("DISCONNECT")) //Client wants to disconnect
				{
					socket.close(); //Close the socket
					proceed = false; //End this communication loop
				} else if(message.getMessage().equals("CHECKPWD")){ //Client wants to check a password
					if(message.getObjContents().size() < 2){
						response = new Envelope("FAIL");
					}
					EncryptedMessage username = (EncryptedMessage)message.getObjContents().get(0);
					EncryptedMessage password = (EncryptedMessage)message.getObjContents().get(1);

					//Decrypt messages
					AESDecrypter aesDecrypter = new AESDecrypter(AESKey);
					String usernameDecr = aesDecrypter.decrypt(username);
					String passwordDecr = aesDecrypter.decrypt(password);

					//Hash password
					byte[] passwordHash = null;
					try {
						DigestSHA3 md = new DigestSHA3(256);
		  				md.update(passwordDecr.getBytes("UTF-8"));
		  				passwordHash = md.digest();
					} catch(Exception ex) {
						ex.printStackTrace();
					}

					if(checkPassword(usernameDecr, passwordHash)){
						response = new Envelope("OK");
					} else {
						response = new Envelope("FAIL");
					}

					output.writeObject(response);

				//Client wants to do a DH exchange
				} else if (message.getMessage().equals("DH")){
					if(message.getObjContents().size() < 3){
						response = new Envelope("FAIL");
					}

					BigInteger p = (BigInteger)message.getObjContents().get(0);
					BigInteger g = (BigInteger)message.getObjContents().get(1);
					BigInteger C = (BigInteger)message.getObjContents().get(2);

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

				 	response = new Envelope("OK");
				 	response.addObject(S);

				 	output.writeObject(response);

				//Client wants to authenticate the server with a random challenge
				} else if (message.getMessage().equals("RANDOM")){
					byte[] challenge = (byte[])message.getObjContents().get(0);

					//Decrypts the sent challenge and sends it back for comparison
					byte[] decryptedChallenge = null;
					try {
						Cipher RSACipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
			            RSACipher.init(Cipher.DECRYPT_MODE, privateKey);
			            //Decrypt the string using the Cipher
			            decryptedChallenge = RSACipher.doFinal(challenge);
					} catch (Exception ex){
						ex.printStackTrace();
					}
					response = new Envelope("OK");
					response.addObject(decryptedChallenge);

					output.writeObject(response);

				//Client wants public key of server
				} else if (message.getMessage().equals("GETPUBLICKEY")){
					response = new Envelope("KEY");
					response.addObject(publicKey);
					output.writeObject(response);
				}
				else
				{
					response = new Envelope("FAIL"); //Server does not understand client request
					output.writeObject(response);
				}
			}while(proceed);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}

	private boolean verifySignature(EncryptedMessage tokenIn, EncryptedMessage signature){
		AESDecrypter tokenDecrypter = new AESDecrypter(AESKey);
		AESDecrypter sigDecrypter = new AESDecrypter(AESKey);

		byte[] tokenBytes = tokenDecrypter.decryptBytes(tokenIn);
		byte[] sigBytes = sigDecrypter.decryptBytes(signature);

		try{
			Signature signaturev = Signature.getInstance("RSA");
			signaturev.initVerify(publicKey);
			signaturev.update(tokenBytes);
			return signaturev.verify(sigBytes);
		} catch(Exception sigex){
			sigex.printStackTrace();
		}
		 
		return false;
	}

	private boolean checkPassword(String username, byte[] password){
		if (my_gs.userList.checkUser(username)){
			byte[] retrievedPassword = my_gs.userList.getPassword(username);
			return Arrays.equals(password, retrievedPassword);
		} else {
			return false;
		}
	}

	//Method to create tokens
	private UserToken createToken(String username)
	{
		//Check that user exists
		if(my_gs.userList.checkUser(username))
		{
			//Issue a new token with server's name, user's name, and user's groups
			UserToken yourToken = new Token(my_gs.name, username, my_gs.userList.getUserGroups(username));
			return yourToken;
		}
		else
		{
			return null;
		}
	}


	//Method to create a user
	private boolean createUser(String username, byte[] password, UserToken yourToken)
	{
		String requester = yourToken.getSubject();

		//Check if requester exists
		if(my_gs.userList.checkUser(requester))
		{
			//Get the user's groups
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administrator
			if(temp.contains("ADMIN"))
			{
				//Does user already exist?
				if(my_gs.userList.checkUser(username))
				{
					return false; //User already exists
				}
				else
				{
					my_gs.userList.addUser(username, password);
					return true;
				}
			}
			else
			{
				return false; //requester not an administrator
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}

	//Method to delete a user
	private boolean deleteUser(String username, UserToken yourToken)
	{
		String requester = yourToken.getSubject();

		//Does requester exist?
		if(my_gs.userList.checkUser(requester))
		{
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administer
			if(temp.contains("ADMIN"))
			{
				//Does user exist?
				if(my_gs.userList.checkUser(username))
				{
					//User needs deleted from the groups they belong
					ArrayList<String> deleteFromGroups = new ArrayList<String>();

					//This will produce a hard copy of the list of groups this user belongs
					for(int index = 0; index < my_gs.userList.getUserGroups(username).size(); index++)
					{
						deleteFromGroups.add(my_gs.userList.getUserGroups(username).get(index));
					}

					//If groups are owned, they must be deleted
					ArrayList<String> deleteOwnedGroup = new ArrayList<String>();

					//Make a hard copy of the user's ownership list
					for(int index = 0; index < my_gs.userList.getUserOwnership(username).size(); index++)
					{
						deleteOwnedGroup.add(my_gs.userList.getUserOwnership(username).get(index));
					}

					//Delete owned groups
					for(int index = 0; index < deleteOwnedGroup.size(); index++)
					{
						//Use the delete group method. Token must be created for this action
						deleteGroup(deleteOwnedGroup.get(index), new Token(my_gs.name, username, deleteOwnedGroup));
					}

					//Delete the user from the user list
					my_gs.userList.deleteUser(username);

					return true;
				}
				else
				{
					return false; //User does not exist

				}
			}
			else
			{
				return false; //requester is not an administer
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}

	private boolean deleteGroup(String groupname, UserToken yourToken){
		String requester = yourToken.getSubject();
		//Check if requesting user exists
		if(my_gs.userList.checkUser(requester)){
			//Get list of all users
			Enumeration<String> groupList = my_gs.userList.getUserList();
			ArrayList<String> ownerOf = my_gs.userList.getUserOwnership(requester);
			//If requester is not owner of group, then deny request
			if(!ownerOf.contains(groupname)){
				return false;
			}
			//Remove ownership and group from owner
			my_gs.userList.removeGroup(requester, groupname);
			my_gs.userList.removeOwnership(requester, groupname);
			while(groupList.hasMoreElements()){
				String thisUser = groupList.nextElement();
				ArrayList<String> thisUserGroups = my_gs.userList.getUserGroups(thisUser);
				if(thisUserGroups.contains(groupname)){
					my_gs.userList.removeGroup(thisUser, groupname);
				}
			}
			return true;
		} else {
			//Doesn't exist
			return false;
		}

	}

	private boolean createGroup(String groupname, UserToken yourToken){
		String requester = yourToken.getSubject();
		//Check if requesting user exists
		if(my_gs.userList.checkUser(requester)){
			//Get list of all users
			Enumeration<String> groupList = my_gs.userList.getUserList();
			//Iterate through each user and compare each group that is owned by every user
			//to the group name that the user seeks to create. If it matches, deny request
			//as group already exists
			while(groupList.hasMoreElements()){
				String thisUser = groupList.nextElement();
				ArrayList<String> thisUserOwns = my_gs.userList.getUserOwnership(thisUser);
				if(thisUserOwns.contains(groupname)){
					return false;
				}
			}
			//Otherwise, add ownership of this group to requester and group to this user
			my_gs.userList.addGroup(requester, groupname);
			my_gs.userList.addOwnership(requester, groupname);

			yourToken = createToken(requester);

			List<String> userGroups = yourToken.getGroups();

			return true;
		} else {
			//User does not exist
			return false;
		}

	}

	private boolean addUserToGroup(String username, String groupname, UserToken yourToken){
		String requester = yourToken.getSubject();
		//Check that token holder and user exist
		if(my_gs.userList.checkUser(requester) && my_gs.userList.checkUser(username)){
			//Check that requester owns group
			if(my_gs.userList.getUserOwnership(requester).contains(groupname)){
				//Check that user isn't already in group
				if(my_gs.userList.getUserGroups(username).contains(groupname)){
					return false;
				} else {
					//Not already in group, add
					my_gs.userList.addGroup(username, groupname);
					return true;
				}
			} else {
				//Isn't owner
				return false;
			}
		} else {
			//Doesn't exist
			return false;
		}
	}

	private boolean deleteUserFromGroup(String username, String groupname, UserToken yourToken){ 
		String requester = yourToken.getSubject();
		//Check that token holder and user exist
		if(my_gs.userList.checkUser(requester) && my_gs.userList.checkUser(username)){
			//Check that requester owns group
			if(my_gs.userList.getUserOwnership(requester).contains(groupname)){
				//Check that user belongs to group
				if(my_gs.userList.getUserGroups(username).contains(groupname)){
					my_gs.userList.removeGroup(username, groupname);
					return true;
				} else {
					//Doesn't belong
					return false;
				}
			} else {
				//Doesn't own group
				return false;
			}
		} else {
			//Doesn't exist
			return false;
		}
	}

	private List<String> listMembers(String group, UserToken yourToken){
		String requester = yourToken.getSubject();
		List<String> members = new ArrayList<String>();
		//Check that requester exists
		if(my_gs.userList.checkUser(requester)){
			ArrayList<String> ownerOf = my_gs.userList.getUserOwnership(requester);
			//If requester is owner of that group
			if(ownerOf.contains(group)){
				//Get list of all users and see if they belong to requester's group
				Enumeration<String> groupList = my_gs.userList.getUserList();
				//Iterate through user list and add that user to the master list if they exist in that group
				while(groupList.hasMoreElements()){
					String thisUser = groupList.nextElement();
					ArrayList<String> thisUsersGroups = my_gs.userList.getUserGroups(thisUser);
					if(thisUsersGroups.contains(group)){
						members.add(thisUser);
					}
				}

				return members;
			} else {
				//Not in group
				return null;
			}
		} else {
			//Doesn't exist
			return null;
		}
	} 

}
