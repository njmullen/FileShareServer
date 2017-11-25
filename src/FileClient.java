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

	private PublicKey groupServerKey = null;
	private AESDecrypter aes = null;
	private Key AESKey = null;
	private int incrementVal = 0;
	private EncryptedMessage encryptedVal = null;
	private PublicKey fileServerKey = null;

	public void setAESKey(Key key){
		AESKey = key;
		//Decrypt the increment value
		AESDecrypter valDecr = new AESDecrypter(AESKey);
		incrementVal = valDecr.decryptInt(encryptedVal);
	}

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

            //Send to FileThread
            try{
            	Envelope message = null, response = null;
            	message = new Envelope("GK");
            	message.addObject(groupServerKey);

            	output.writeObject(message);

            	response = (Envelope)input.readObject();
            	if(response.getMessage().equals("OK")){
            		return true;
            	}
            	return false;
            }
            catch(Exception ex){
            	ex.printStackTrace();
            }
            return false;
		} else {
			System.out.println("GroupServer/FileServer error");
			System.exit(0);
			return false;
		}
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
				fileServerKey = publicKey;
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

	public boolean delete(String filename, EncryptedToken token) {
		String remotePath;
		if (filename.charAt(0)=='/') {
			remotePath = filename.substring(1);
		}
		else {
			remotePath = filename;
		}

		//Encrypt
		AESEncrypter fileEnc = new AESEncrypter(AESKey);

		//Encrypt filename and token and send to server
		EncryptedMessage encryptedFile = fileEnc.encrypt(remotePath);

		Envelope env = new Envelope("DELETEF"); //Success
	    env.addObject(encryptedFile);
	    env.addObject(token);

	    //Add increment value
		EncryptedMessage increment = increment();
		env.addObject(increment);

	    try {
			output.writeObject(env);
		    env = (Envelope)input.readObject();

		    //Check increment value
			EncryptedMessage incrementIn = (EncryptedMessage)env.getObjContents().get(0);
			if(!checkIncrement(incrementIn)){
				System.out.println("Client Replay detected");
				System.exit(0);
			}
		    
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

	public boolean download(String sourceFile, String destFile, EncryptedToken token) {
		if (sourceFile.charAt(0)=='/') {
			sourceFile = sourceFile.substring(1);
		}

		File file = new File(destFile);
	    try {			
			System.out.println("Download");
		    if (!file.exists()){
		    	file.createNewFile();
			    FileOutputStream fos = new FileOutputStream(file);
			    
			    Envelope env = new Envelope("DOWNLOADF"); //Success

			    AESEncrypter fileEnc = new AESEncrypter(AESKey);
			    EncryptedMessage sourceEnc = fileEnc.encrypt(sourceFile);
			    env.addObject(sourceEnc);
			    env.addObject(token);
			    //Add increment value
				EncryptedMessage increment = increment();
				env.addObject(increment);
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
			    	//Check increment value
				 	 EncryptedMessage incrementIn = (EncryptedMessage)env.getObjContents().get(0);
				  	 if(!checkIncrement(incrementIn)){
					  	System.out.println("Client Replay detected");
					 	System.exit(0);
					 }
			    	 fos.close();
						System.out.printf("\nTransfer successful file %s\n", sourceFile);
						env = new Envelope("OK"); //Success
						output.writeObject(env);
				}
				else {
						System.out.printf("Error reading file %s (%s)\n", sourceFile, env.getMessage());
						file.delete();
						//Check increment value
					 	 EncryptedMessage incrementIn = (EncryptedMessage)env.getObjContents().get(0);
					  	 if(!checkIncrement(incrementIn)){
						  	System.out.println("Client Replay detected");
						 	System.exit(0);
						 }
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

	public boolean upload(String sourceFile, String destFile, String group, EncryptedToken token) {	
		if (destFile.charAt(0)!='/') {
			 destFile = "/" + destFile;
		}
		
		try {
		 	//Encrypt Everything
		 	AESEncrypter destEnc = new AESEncrypter(AESKey);
		 	AESEncrypter groupEnc = new AESEncrypter(AESKey);

		 	EncryptedMessage dest = destEnc.encrypt(destFile);
		 	EncryptedMessage _group = groupEnc.encrypt(group);

			 Envelope message = null, env = null;
			 //Tell the server to return the member list
			 message = new Envelope("UPLOADF");
			 message.addObject(dest);
			 message.addObject(_group);
			 message.addObject(token); //Add requester's token
			 //Add increment value
			 EncryptedMessage increment = increment();
			 message.addObject(increment);
			 output.writeObject(message);
			
			 
			 FileInputStream fis = new FileInputStream(sourceFile);
			 
			 env = (Envelope)input.readObject();
			 
			 //If server indicates success, return the member list
			 if(env.getMessage().equals("READY")){
				System.out.printf("Meta data upload successful\n");
			 } else {
				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 //Check increment value
			 	 EncryptedMessage incrementIn = (EncryptedMessage)env.getObjContents().get(0);
			  	 if(!checkIncrement(incrementIn)){
				  	System.out.println("Client Replay detected");
				 	System.exit(0);
				 }
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
				
				AESEncrypter bufEnc = new AESEncrypter(AESKey);

				EncryptedMessage bufSend = bufEnc.encrypt(buf);

				message.addObject(bufSend);
				message.addObject(new Integer(n));
				
				output.writeObject(message);
				
				env = (Envelope)input.readObject();
								
			 } while (fis.available()>0);		 
					 
			 //If server indicates success, return the member list
			 if(env.getMessage().compareTo("READY") == 0) { 
				
				message = new Envelope("EOF");
				output.writeObject(message);
				
				env = (Envelope)input.readObject();

				//Check increment value
			 	EncryptedMessage incrementIn = (EncryptedMessage)env.getObjContents().get(0);
			  	if(!checkIncrement(incrementIn)){
				  	System.out.println("Client Replay detected");
				 	System.exit(0);
				}

				if(env.getMessage().compareTo("OK")==0) {
					System.out.printf("\nFile data upload successful\n");
				} else{
					 System.out.printf("\nUpload failed: %s\n", env.getMessage());
					 return false;
				}

			} else {
				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 //Check increment value
			 	 EncryptedMessage incrementIn = (EncryptedMessage)env.getObjContents().get(0);
			  	 if(!checkIncrement(incrementIn)){
				  	System.out.println("Client Replay detected");
				 	System.exit(0);
				 }
				 return false;
			 }
			 
		 } catch(Exception e1){
			System.err.println("Error: " + e1.getMessage());
			e1.printStackTrace(System.err);
			return false;
		 }

		 return true;
	}

	@SuppressWarnings("unchecked")
	public List<String> listFiles(EncryptedToken token) {
		 try
		 {
			 Envelope message = null, e = null;
			 //Tell the server to return the member list
			 message = new Envelope("LFILES");
			 message.addObject(token); //Add requester's token

			 //Add increment value
			 EncryptedMessage increment = increment();
			 message.addObject(increment);
			 output.writeObject(message); 
			 
			 e = (Envelope)input.readObject();

			 //If server indicates success, return the member list
			 int listSize = 0;
			 if(e.getMessage().equals("OK"))
			 { 
				listSize = (int)e.getObjContents().get(0);
				List<String> fileList = new ArrayList<String>();
				for(int i = 1; i < listSize + 1; i++){
			 		EncryptedMessage encList = (EncryptedMessage)e.getObjContents().get(i);
			 		AESDecrypter listDecr = new AESDecrypter(AESKey);
			 		String thisMember = listDecr.decrypt(encList);
			 		fileList.add(thisMember);
			 	}

			 	//Check increment value
			 	EncryptedMessage incrementIn = (EncryptedMessage)e.getObjContents().get(listSize + 1);
			  	if(!checkIncrement(incrementIn)){
				  	System.out.println("Client Replay detected");
				 	System.exit(0);
				}

			 	return fileList;
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
				dhSig.initVerify(fileServerKey);
				dhSig.update(S.toByteArray());
				if(!dhSig.verify(sSigned)){
					System.out.println("Unable to verify DH signature");
					System.exit(0);
				}

				//Grabs the encrypted increment value which will be decrypted
				//once the client calculates the shared AES key
				encryptedVal = (EncryptedMessage)response.getObjContents().get(2);
				return S;
			}
			return null;
	 	} catch (Exception ex){
	 		ex.printStackTrace();
	 	}
	 	
	 	return null;
	 }


}

