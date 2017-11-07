/* FileClient provides all the client functionality regarding the file server */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
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

public class FileClient extends Client implements FileClientInterface {

	PublicKey groupServerKey;

	public boolean getGroupServerKey(String server, int port){
		GroupClient gc = new GroupClient();
		gc.connect(server, port);
		if (gc.isConnected()){
			//Get the public key
			groupServerKey = gc.getPublicKey();
			//Generate a random challenge and send to server to encrypt
            Random random = new Random();
            BigInteger challenge = new BigInteger(1024, random);
            byte[] challengeBytes = challenge.toByteArray();
            byte[] encryptedChallenge = null;
            try {
                Cipher RSACipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
                RSACipher.init(Cipher.ENCRYPT_MODE, groupServerKey);
                //Encrypt the string using the Cipher
                encryptedChallenge = RSACipher.doFinal(challengeBytes);
            } catch (Exception rsaExf){
                rsaExf.printStackTrace();
            }
            byte[] challengeRecieved = gc.sendRandomChallenge(encryptedChallenge);
            if (!Arrays.equals(challengeRecieved, challengeBytes)){
                System.out.println("Unable to authenticate server");
                gc.disconnect();
                System.exit(0);
            }
            return true;
		} else {
			System.out.println("GroupServer/FileServer error");
			System.exit(0);
			return false;
		}
	}

	public byte[] sendRandomChallenge(byte[] challenge){
		//Decrypt the random challenge with private key and return it
		Security.addProvider(new BouncyCastleProvider());
		PrivateKey privateKey = null;
		byte[] decryptedChallenge = null;
		try {
			File privateKeyFile = new File("filePrivateKey");
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
			File publicKeyFile = new File("filePublicKey");
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

	public boolean delete(String filename, UserToken token) {
		String remotePath;
		if (filename.charAt(0)=='/') {
			remotePath = filename.substring(1);
		}
		else {
			remotePath = filename;
		}
		Envelope env = new Envelope("DELETEF"); //Success
	    env.addObject(remotePath);
	    env.addObject(token);
	    try {
			output.writeObject(env);
		    env = (Envelope)input.readObject();
		    
			if (env.getMessage().compareTo("OK")==0) {
				System.out.printf("File %s deleted successfully\n", filename);				
			}
			else {
				System.out.printf("Error deleting file %s (%s)\n", filename, env.getMessage());
				return false;
			}			
		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (ClassNotFoundException e1) {
			e1.printStackTrace();
		}
	    	
		return true;
	}

	public boolean download(String sourceFile, String destFile, UserToken token) {
				if (sourceFile.charAt(0)=='/') {
					sourceFile = sourceFile.substring(1);
				}
		
				File file = new File(destFile);
			    try {
			    				
				
				    if (!file.exists()) {
				    	file.createNewFile();
					    FileOutputStream fos = new FileOutputStream(file);
					    
					    Envelope env = new Envelope("DOWNLOADF"); //Success
					    env.addObject(sourceFile);
					    env.addObject(token);
					    output.writeObject(env); 
					
					    env = (Envelope)input.readObject();
					    
						while (env.getMessage().compareTo("CHUNK")==0) { 
								fos.write((byte[])env.getObjContents().get(0), 0, (Integer)env.getObjContents().get(1));
								System.out.printf(".");
								env = new Envelope("DOWNLOADF"); //Success
								output.writeObject(env);
								env = (Envelope)input.readObject();									
						}										
						fos.close();
						
					    if(env.getMessage().compareTo("EOF")==0) {
					    	 fos.close();
								System.out.printf("\nTransfer successful file %s\n", sourceFile);
								env = new Envelope("OK"); //Success
								output.writeObject(env);
						}
						else {
								System.out.printf("Error reading file %s (%s)\n", sourceFile, env.getMessage());
								file.delete();
								return false;								
						}
				    }    
					 
				    else {
						System.out.printf("Error couldn't create file %s\n", destFile);
						return false;
				    }
								
			
			    } catch (IOException e1) {
			    	
			    	System.out.printf("Error couldn't create file %s\n", destFile);
			    	return false;
			    
					
				}
			    catch (ClassNotFoundException e1) {
					e1.printStackTrace();
				}
				 return true;
	}

	@SuppressWarnings("unchecked")
	public List<String> listFiles(UserToken token) {
		 try
		 {
			 Envelope message = null, e = null;
			 //Tell the server to return the member list
			 message = new Envelope("LFILES");
			 message.addObject(token); //Add requester's token
			 output.writeObject(message); 
			 
			 e = (Envelope)input.readObject();
			 
			 //If server indicates success, return the member list
			 if(e.getMessage().equals("OK"))
			 { 
				return (List<String>)e.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
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

	public boolean upload(String sourceFile, String destFile, String group,
			UserToken token) {
			
		if (destFile.charAt(0)!='/') {
			 destFile = "/" + destFile;
		 }
		
		try
		 {
			 
			 Envelope message = null, env = null;
			 //Tell the server to return the member list
			 message = new Envelope("UPLOADF");
			 message.addObject(destFile);
			 message.addObject(group);
			 message.addObject(token); //Add requester's token
			 output.writeObject(message);
			
			 
			 FileInputStream fis = new FileInputStream(sourceFile);
			 
			 env = (Envelope)input.readObject();
			 
			 //If server indicates success, return the member list
			 if(env.getMessage().equals("READY"))
			 { 
				System.out.printf("Meta data upload successful\n");
				
			}
			 else {
				
				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			 }
			 
		 	
			 do {
				 byte[] buf = new byte[4096];
				 	if (env.getMessage().compareTo("READY")!=0) {
				 		System.out.printf("Server error: %s\n", env.getMessage());
				 		return false;
				 	}
				 	message = new Envelope("CHUNK");
					int n = fis.read(buf); //can throw an IOException
					if (n > 0) {
						System.out.printf(".");
					} else if (n < 0) {
						System.out.println("Read error");
						return false;
					}
					
					message.addObject(buf);
					message.addObject(new Integer(n));
					
					output.writeObject(message);
					
					
					env = (Envelope)input.readObject();
					
										
			 }
			 while (fis.available()>0);		 
					 
			 //If server indicates success, return the member list
			 if(env.getMessage().compareTo("READY")==0)
			 { 
				
				message = new Envelope("EOF");
				output.writeObject(message);
				
				env = (Envelope)input.readObject();
				if(env.getMessage().compareTo("OK")==0) {
					System.out.printf("\nFile data upload successful\n");
				}
				else {
					
					 System.out.printf("\nUpload failed: %s\n", env.getMessage());
					 return false;
				 }
				
			}
			 else {
				
				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			 }
			 
		 }catch(Exception e1)
			{
				System.err.println("Error: " + e1.getMessage());
				e1.printStackTrace(System.err);
				return false;
				}
		 return true;
	}

}

