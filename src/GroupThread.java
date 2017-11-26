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
	private int incrementVal = 0;

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
				Envelope message = null;
				try {
					message = (Envelope)input.readObject();
					System.out.println("Request received: " + message.getMessage());
				} catch(EOFException e) {
					System.out.println("A User Disconnected");
					break;
				}
				Envelope response;

				if(message.getMessage().equals("GET"))//Client wants a token
				{
					EncryptedMessage usernameEnc = (EncryptedMessage)message.getObjContents().get(0); //Get the username
					AESDecrypter aesDecrypter = new AESDecrypter(AESKey);
					String username = aesDecrypter.decrypt(usernameEnc);

					EncryptedMessage fileServerEnc = (EncryptedMessage)message.getObjContents().get(1); //Get the Fileserver name
					AESDecrypter fileServerDecr = new AESDecrypter(AESKey);
					String fileServer = fileServerDecr.decrypt(fileServerEnc);

					EncryptedMessage filePortEnc = (EncryptedMessage)message.getObjContents().get(2); //Get the File port
					AESDecrypter filePortDecr = new AESDecrypter(AESKey);
					String filePortString = filePortDecr.decrypt(filePortEnc);
					int filePort = Integer.parseInt(filePortString);

					//Check increment
					EncryptedMessage increment = (EncryptedMessage)message.getObjContents().get(3);
					if(!checkIncrement(increment)){
						System.out.println("GET TOKEN Server Replay detected");
						System.exit(0);
					}

					if(username == null || fileServer == null)
					{
						response = new Envelope("FAIL");
						response.addObject(null);
						output.writeObject(response);
					}
					else
					{
						UserToken yourToken = createToken(username, fileServer, filePort); //Create a token

						String issuer = yourToken.getIssuer();
						String subject = yourToken.getSubject();
						List<String> groupList = yourToken.getGroups();
						String fileServerT = yourToken.getFileServer();
						int filePortT = yourToken.getFilePort();

						List<String> newGroupList = new ArrayList<String>();
						for (int i = 0; i < groupList.size(); i++){
							newGroupList.add(groupList.get(i));
						}
						Token token = new Token(issuer, subject, newGroupList, fileServerT, filePortT);

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

						//Generate list of encrypted group keys to send to user
						ArrayList<GroupKey> groupKeys = getGroupKeys(newGroupList);

						// Print out groupnames that server knows of
						// TROUBLESHOOTING
						System.out.println("GroupKeySize in thead "+groupKeys.size());
						for( GroupKey k : groupKeys ) {
							System.out.println(k.getName());
						}

						ArrayList<EncryptedGroupKey> encGroupKeys = new ArrayList<EncryptedGroupKey>();
						for(int i = 0; i < groupKeys.size(); i++){
							encGroupKeys.add(groupKeys.get(i).getEncrypted(AESKey));
						}

						response.addObject(encGroupKeys);


						//Increment value
						EncryptedMessage incrementSend = increment();
						response.addObject(incrementSend);

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

								//Check increment
								EncryptedMessage increment = (EncryptedMessage)message.getObjContents().get(4);
								if(!checkIncrement(increment)){
									System.out.println("CUSER Server Replay detected");
									System.exit(0);
								}

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
					//Increment value
					EncryptedMessage incrementSend = increment();
					response.addObject(incrementSend);
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
								//Check increment
								EncryptedMessage increment = (EncryptedMessage)message.getObjContents().get(3);
								if(!checkIncrement(increment)){
									System.out.println("DUSER Server Replay detected");
									System.exit(0);
								}
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
					//Increment value
					EncryptedMessage incrementSend = increment();
					response.addObject(incrementSend);
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
								EncryptedMessage groupName = (EncryptedMessage)message.getObjContents().get(0); //Extract the username
								EncryptedMessage tokenIn = (EncryptedMessage)message.getObjContents().get(1); //Extract the token
								EncryptedMessage signIn = (EncryptedMessage)message.getObjContents().get(2);
								//Check increment
								EncryptedMessage increment = (EncryptedMessage)message.getObjContents().get(3);
								if(!checkIncrement(increment)){
									System.out.println("CGROUP Server Replay detected");
									System.exit(0);
								}
								//Check token signature
								if(!verifySignature(tokenIn, signIn)){
									System.out.println("Token error");
									System.exit(0);
								}

								AESDecrypter groupDecr = new AESDecrypter(AESKey);
								AESDecrypter tokenDecr = new AESDecrypter(AESKey);
								String groupPlain = groupDecr.decrypt(groupName);
								byte[] tokenPlain = tokenDecr.decryptBytes(tokenIn);
								Token yourToken = new Token(tokenPlain);

								if(createGroup(groupPlain, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}
					//Increment value
					EncryptedMessage incrementSend = increment();
					response.addObject(incrementSend);
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
								EncryptedMessage groupName = (EncryptedMessage)message.getObjContents().get(0); //Extract the username
								EncryptedMessage tokenIn = (EncryptedMessage)message.getObjContents().get(1); //Extract the token
								EncryptedMessage signIn = (EncryptedMessage)message.getObjContents().get(2);
								//Check increment
								EncryptedMessage increment = (EncryptedMessage)message.getObjContents().get(3);
								if(!checkIncrement(increment)){
									System.out.println("DGROUP Server Replay detected");
									System.exit(0);
								}
								if(!verifySignature(tokenIn, signIn)){
									System.out.println("Token error");
									System.exit(0);
								}

								AESDecrypter groupDecr = new AESDecrypter(AESKey);
								AESDecrypter tokenDecr = new AESDecrypter(AESKey);
								String groupPlain = groupDecr.decrypt(groupName);
								byte[] tokenPlain = tokenDecr.decryptBytes(tokenIn);
								Token yourToken = new Token(tokenPlain);

								if(deleteGroup(groupPlain, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}
					//Increment value
					EncryptedMessage incrementSend = increment();
					response.addObject(incrementSend);
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
								EncryptedMessage groupName = (EncryptedMessage)message.getObjContents().get(0); //Extract the username
								EncryptedMessage tokenIn = (EncryptedMessage)message.getObjContents().get(1); //Extract the token
								EncryptedMessage signIn = (EncryptedMessage)message.getObjContents().get(2);
								//Check increment
								EncryptedMessage increment = (EncryptedMessage)message.getObjContents().get(3);
								if(!checkIncrement(increment)){
									System.out.println("Server Replay detected");
									System.exit(0);
								}
								if(!verifySignature(tokenIn, signIn)){
									System.out.println("Token error");
									System.exit(0);
								}

								AESDecrypter groupDecr = new AESDecrypter(AESKey);
								AESDecrypter tokenDecr = new AESDecrypter(AESKey);
								String groupPlain = groupDecr.decrypt(groupName);
								byte[] tokenPlain = tokenDecr.decryptBytes(tokenIn);
								Token yourToken = new Token(tokenPlain);

								/////poop

								List<String> members = listMembers(groupPlain, yourToken);
								if(members != null) {
									int membersize = members.size();

									response = new Envelope("OK"); //Success
									response.addObject(membersize);

									for(int i = 0; i < members.size(); i++){
										AESEncrypter listEncr = new AESEncrypter(AESKey);
										EncryptedMessage listEncrd = listEncr.encrypt(members.get(i));
										response.addObject(listEncrd);
									}
								} else {
									response = new Envelope("FAIL");
								}


							}
						}
					}
					//Increment value
					EncryptedMessage incrementSend = increment();
					response.addObject(incrementSend);
					output.writeObject(response);
				}
				else if(message.getMessage().equals("AUSERTOGROUP")) //Client wants to add user to a group
				{
				    if(message.getObjContents().size() < 4)
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
									if(message.getObjContents().get(3) != null)
									{
										EncryptedMessage usernameToAdd = (EncryptedMessage)message.getObjContents().get(0); //Extract the username
										EncryptedMessage groupToAdd = (EncryptedMessage)message.getObjContents().get(1); //Extract the username
										EncryptedMessage tokenIn = (EncryptedMessage)message.getObjContents().get(2); //Extract the token
										EncryptedMessage signIn = (EncryptedMessage)message.getObjContents().get(3); //extract signature
										//Check increment
										EncryptedMessage increment = (EncryptedMessage)message.getObjContents().get(4);
										if(!checkIncrement(increment)){
											System.out.println("Server Replay detected");
											System.exit(0);
										}
										if(!verifySignature(tokenIn, signIn)){
											System.out.println("Token error");
											System.exit(0);
										}

										AESDecrypter usernameDecr = new AESDecrypter(AESKey);
										AESDecrypter groupDecr = new AESDecrypter(AESKey);
										AESDecrypter tokenDecr = new AESDecrypter(AESKey);

										String userPlain = usernameDecr.decrypt(usernameToAdd);
										String groupPlain = groupDecr.decrypt(groupToAdd);
										byte[] tokenPlain = tokenDecr.decryptBytes(tokenIn);
										Token yourToken = new Token(tokenPlain);

										if(addUserToGroup(userPlain, groupPlain, yourToken))
										{
											response = new Envelope("OK"); //Success
										}
									}
								}
							}
						}
					}
					//Increment value
					EncryptedMessage incrementSend = increment();
					response.addObject(incrementSend);
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
									EncryptedMessage userName = (EncryptedMessage)message.getObjContents().get(0);
									EncryptedMessage groupName = (EncryptedMessage)message.getObjContents().get(1); //Extract the username
									EncryptedMessage tokenIn = (EncryptedMessage)message.getObjContents().get(2); //Extract the token
									EncryptedMessage signIn = (EncryptedMessage)message.getObjContents().get(3);
									//Check increment
									EncryptedMessage increment = (EncryptedMessage)message.getObjContents().get(4);
									if(!checkIncrement(increment)){
										System.out.println("Server Replay detected");
										System.exit(0);
									}
									AESDecrypter groupDecr = new AESDecrypter(AESKey);
									AESDecrypter userDecr = new AESDecrypter(AESKey);
									AESDecrypter tokenDecr = new AESDecrypter(AESKey);
									String groupPlain = groupDecr.decrypt(groupName);
									String userPlain = userDecr.decrypt(userName);
									byte[] tokenPlain = tokenDecr.decryptBytes(tokenIn);
									Token yourToken = new Token(tokenPlain);

									if(!verifySignature(tokenIn, signIn)){
										System.out.println("Token error");
										System.exit(0);
									}



									if(deleteUserFromGroup(userPlain, groupPlain, yourToken))
									{
										response = new Envelope("OK"); //Success
									}
								}
							}
						}
					}
					//Increment value
					EncryptedMessage incrementSend = increment();
					response.addObject(incrementSend);
					output.writeObject(response);
				}
				else if(message.getMessage().equals("DISCONNECT")) //Client wants to disconnect
				{
					socket.close(); //Close the socket
					proceed = false; //End this communication loop
				}
				else if(message.getMessage().equals("CHECKPWD")) //Client wants to check a password
				{
					if(message.getObjContents().size() < 2){
						response = new Envelope("FAIL");
					}
					EncryptedMessage username = (EncryptedMessage)message.getObjContents().get(0);
					EncryptedMessage password = (EncryptedMessage)message.getObjContents().get(1);
					EncryptedMessage increment = (EncryptedMessage)message.getObjContents().get(2);

					//Decrypt messages
					AESDecrypter aesDecrypter = new AESDecrypter(AESKey);
					String usernameDecr = aesDecrypter.decrypt(username);
					String passwordDecr = aesDecrypter.decrypt(password);

					//Check increment
					if(!checkIncrement(increment)){
						System.out.println("Server Replay detected");
						System.exit(0);
					}

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

					//Increment value
					EncryptedMessage incrementSend = increment();
					response.addObject(incrementSend);

					output.writeObject(response);
				}
				else if (message.getMessage().equals("DH")) //Client wants to perform a Diffie-Hellman exchange
				{
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

				 	//Write out and set increment value
				 	Random rand = new Random();
				 	incrementVal = rand.nextInt();
				 	AESEncrypter valEncr = new AESEncrypter(AESKey);
				 	EncryptedMessage value = valEncr.encrypt(incrementVal);
				 	response.addObject(value);

				 	output.writeObject(response);
				}
				else if (message.getMessage().equals("GETPUBLICKEY")) //Client wants public key of server
				{
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
			System.out.println("User Disconnected");
		}
	}

	private boolean verifySignature(EncryptedMessage tokenIn, EncryptedMessage signature)
	{
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

	private boolean checkPassword(String username, byte[] password)
	{
		if (my_gs.userList.checkUser(username)){
			byte[] retrievedPassword = my_gs.userList.getPassword(username);
			return Arrays.equals(password, retrievedPassword);
		} else {
			return false;
		}
	}

	//Method to create tokens
	private UserToken createToken(String username, String fileServer, int filePort)
	{
		//Check that user exists
		if(my_gs.userList.checkUser(username))
		{
			//Issue a new token with server's name, user's name, and user's groups
			UserToken yourToken = new Token(my_gs.name, username, my_gs.userList.getUserGroups(username), fileServer, filePort);
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
						deleteGroup(deleteOwnedGroup.get(index), new Token(my_gs.name, username, deleteOwnedGroup, yourToken.getFileServer(), yourToken.getFilePort()));
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

	private boolean deleteGroup(String groupname, UserToken yourToken)
	{
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

	private boolean createGroup(String groupname, UserToken yourToken)
	{
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
			genNewGroupKey(groupname);
			yourToken = createToken(requester, yourToken.getFileServer(), yourToken.getFilePort());
			return true;
		} else {
			//User does not exist
			return false;
		}
	}

	private boolean addUserToGroup(String username, String groupname, UserToken yourToken)
	{
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

	private boolean deleteUserFromGroup(String username, String groupname, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		//Check that token holder and user exist
		if(my_gs.userList.checkUser(requester) && my_gs.userList.checkUser(username)){
			//Check that requester owns group
			if(my_gs.userList.getUserOwnership(requester).contains(groupname)){
				//Check that user belongs to group
				if(my_gs.userList.getUserGroups(username).contains(groupname)){
					my_gs.userList.removeGroup(username, groupname);
					genNewGroupKey(groupname);
					yourToken = createToken(requester, yourToken.getFileServer(), yourToken.getFilePort());
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

	private List<String> listMembers(String group, UserToken yourToken)
	{
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

	public EncryptedMessage increment()
	{
		incrementVal++;
		AESEncrypter encr = new AESEncrypter(AESKey);
		EncryptedMessage incrementEncrypted = encr.encrypt(incrementVal);
		return incrementEncrypted;
	}

	private boolean checkIncrement(EncryptedMessage incrementEnc)
	{
		AESDecrypter aesDecr = new AESDecrypter(AESKey);
		int incrementSent = aesDecr.decryptInt(incrementEnc);
		incrementVal++;

		if(incrementVal != incrementSent){
			return false;
		} else{
			return true;
		}
	}

	private ArrayList<GroupKey> getGroupKeys(List<String> groupNames)
	{
		//Read in all group keys
		byte[] allBytes = new byte[1];
		try{
			File groupKeysFile = new File("groupKeyList");
			FileInputStream in = new FileInputStream(groupKeysFile);
			allBytes = new byte[in.available()];
			in.read(allBytes);
			in.close();
		}
		catch(Exception ex){
			ex.printStackTrace();
		}

		//Parse file text to compile a list of applicable keys
		ArrayList<GroupKey> keyList = new ArrayList<GroupKey>();
		StringBuilder name = new StringBuilder();
		//StringBuilder form = new StringBuilder();
		int i = 0;
		boolean proceed = true;
		boolean parsingName = true;
		//boolean parsingFormat = false;
		while(proceed){
			//Check bound
			if(i >= allBytes.length){
				proceed = false;
			}
			//Parse Group Name
			else if(parsingName){
				char c = (char) allBytes[i++];
				if(c == '|'){ //Reached the end of the group name

					//Check if group name is in the list of groups the user belongs to
					if(groupNames.contains(name.toString())){
						parsingName = false;
					}
					else{
						//Flush group name
						name = new StringBuilder();
						//Traverse to beginning of next group name
						while(c != '|'){
							c = (char) allBytes[i++];
						}

					}
				}
				else{
					name.append(c);
				}
			}

			// //Parse format
			// else if(parsingFormat){
			// 	char c = (char) allBytes[i++];
			// 	if(c == "|"){
			// 		parsingFormat = false;
			// 	}
			// 	else{
			// 		form.append(c);
			// 	}
			// }

			//Parse key
			else{
				//Fill new byte[] with Base64 encoded key bytes
				byte[] keyBytes = new byte[24];
				int j = i + 23;
				int k = 0;
				assert (j < allBytes.length);
				while(i <= j){
					keyBytes[k++] = allBytes[i++];
				}

				//Check that next character is the delimeter
				if((char) allBytes[i++] != '|'){
					System.out.printf("\n>>>Something went wrong while parsing group key\n");
					System.out.printf(">>>Group Name: " + name.toString() + "\n");
					System.out.printf(">>>KeyBytes Processed: " + new String(keyBytes) + "\n\n");
					proceed = false;
					break;
				}

				//Create a Key from keyBytes
				byte[] decodedKey = Base64.getDecoder().decode(keyBytes);
				SecretKey key = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

				//Create new GroupKey and add to list
				keyList.add(new GroupKey(name.toString(), key));

				//Flush name
				name = new StringBuilder();
				parsingName = true;
			}
		}

		return keyList;
	}
	private void genNewGroupKey(String groupname) {
		//Generate 128-bit AES key for file encryption
		try{
			KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
			keyGen.init(128);
			SecretKey key = keyGen.generateKey();

			//Write key to file
			//Format: [group name 1] | [key 1] || [group name 2] | [key 2] || ...
			FileOutputStream groupKeyWrite = new FileOutputStream("groupKeyList", true);
			byte[] keyBytes = Base64.getEncoder().encode(key.getEncoded());
			// String format = key.getFormat();
			groupKeyWrite.write(groupname.getBytes());
			// groupKeyWrite.write(new String("|").getBytes());
			// groupKeyWrite.write(format.getBytes());
			groupKeyWrite.write(new String("|").getBytes());
			groupKeyWrite.write(keyBytes);
			groupKeyWrite.write(new String("|").getBytes());
			groupKeyWrite.close();
		}
		catch (Exception ex){
			ex.printStackTrace();
		}
	}
}
