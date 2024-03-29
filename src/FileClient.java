/* FileClient provides all the client functionality regarding the file server */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.*;
import java.util.Base64;

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

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
	private int IVSIZE = 16;
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

	public boolean download(String sourceFile, String destFile, EncryptedToken token, ArrayList<GroupKeyList> groupKeys) {
		if (sourceFile.charAt(0)=='/') {
			sourceFile = sourceFile.substring(1);
		}

		File file = new File(destFile);
	    try {
		    	
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

			    String group = null;
				byte[] fileEncKey = null;

			    //Receive the group from the server
				if(env.getMessage().compareTo("GROUP") == 0){
					if (env.getObjContents().size() < 2) {
						System.out.println("Error in GROUP, message length < 2, missing keyed hash");
					}
		
					AESDecrypter groupDec = new AESDecrypter(AESKey);
					group = groupDec.decrypt((EncryptedMessage)env.getObjContents().get(0));

					AESDecrypter keyedHashDec = new AESDecrypter(AESKey);
					fileEncKey = keyedHashDec.decryptBytes((EncryptedMessage)env.getObjContents().get(1));

					//Check increment value
					EncryptedMessage incrementIn = (EncryptedMessage)env.getObjContents().get(2);
					if(!checkIncrement(incrementIn)){
						System.out.println("Client Replay detected");
						System.exit(0);
					}
				} else{
					System.out.printf("Error: Could not retrieve group for file\n");
					//Check increment value
					EncryptedMessage incrementIn = (EncryptedMessage)env.getObjContents().get(0);
					if(!checkIncrement(incrementIn)){
						System.out.println("Client Replay detected");
						System.exit(0);
					}
					System.out.printf("Message contents: %s\n", env.getMessage());
					return false;
				}

				if(group == null){
					System.out.println("Error: Group not sent");
				}
				if(fileEncKey == null) {
					System.out.println("Error: Keyedhash not sent");
				}

				//Grab correct key from groupslist by comparing the hash of the
				//file on the server with the hash of the groups key
				Key groupKey = null;
				for(int i = 0; i < groupKeys.size(); i++){
					if(groupKeys.get(i).getName().compareTo(group) == 0){
						boolean theresAKey = false;
						for( Key gKey : groupKeys.get(i).getKeys() ) {
							if (Arrays.equals(getKeyedHash(gKey), fileEncKey)) {
								groupKey = gKey;
								theresAKey = true;
								break;
							} else {
								//
							}
						}
						if (!theresAKey) {
							System.out.println("Error: No matching group keyedhash to filekeyedhash");
							throw new IOException();
						}
						break;
					}
				}

				env = (Envelope)input.readObject();
				file.createNewFile();
			    FileOutputStream fos = new FileOutputStream(file);

			    //Read in IvSpec and entire encrypted file
			    boolean readingIV = true;
			    byte[] ivBytes = new byte[1];
			    ArrayList<Byte> encBytes = new ArrayList<Byte>();
				while (env.getMessage().compareTo("CHUNK")==0) {
					byte[] bytesIn = (byte[])env.getObjContents().get(0);
					int messageSize = (Integer)env.getObjContents().get(1); //We do not want the null term
					int ind = 0;

					//Check if reading the IVSpec
					if(readingIV){
						ivBytes = new byte[IVSIZE];
						for(int i = 0; i < IVSIZE; i++){
							ivBytes[i] = bytesIn[i];
						}

						readingIV = false;
						ind = IVSIZE;
					}

					while(ind < messageSize){
						encBytes.add(bytesIn[ind++]);
					}

					System.out.printf(".");
					env = new Envelope("DOWNLOADF"); //Success
					output.writeObject(env);
					env = (Envelope)input.readObject();
				}

				//Decrypt and write the file
				byte[] encFileBytes = new byte[encBytes.size()];
				for(int i = 0; i < encFileBytes.length; i++){
					encFileBytes[i] = encBytes.get(i);
				}
				IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

				//Decode to Base64
				byte[] decodedBytes = Base64.getDecoder().decode(encFileBytes);

				EncryptedMessage encFile = new EncryptedMessage(decodedBytes, ivSpec);

				AESDecrypter fileDec = new AESDecrypter(groupKey);
				byte[] decFileBytes = fileDec.decryptBytes(encFile);

				fos.write(decFileBytes);
				fos.close();

			    if(env.getMessage().compareTo("EOF")==0) {
			    	fos.close();
					System.out.printf("\nTransfer successful file %s\n", sourceFile);
					env = new Envelope("OK"); //Success
					//Add increment value
					EncryptedMessage increment2 = increment();
					env.addObject(increment2);
					output.writeObject(env);
				} else {
					System.out.printf("Error reading file %s (%s)\n", sourceFile, env.getMessage());
					file.delete();
					return false;
				}
	    } catch (IOException e1) {
			e1.printStackTrace();
	    	System.out.printf("Error couldn't create file %s\n", destFile);
	    	return false;
		}
	    catch (ClassNotFoundException e1) {
			e1.printStackTrace();
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
			 if(e.getMessage().equals("OK")){
				int size = (int)e.getObjContents().get(0);
				List<String> fileList = new ArrayList<String>();
				for(int i = 1; i < size + 1; i++){
			 		EncryptedMessage encList = (EncryptedMessage)e.getObjContents().get(i);
			 		AESDecrypter listDecr = new AESDecrypter(AESKey);
			 		String thisMember = listDecr.decrypt(encList);
			 		fileList.add(thisMember);
			 	}
			 	//Check increment value
				EncryptedMessage incrementIn = (EncryptedMessage)e.getObjContents().get(size + 1);
				if(!checkIncrement(incrementIn)){
					System.out.println("Client Replay detected");
					System.exit(0);
				}
			 	return fileList;
			 } else {
			 	System.out.println("Error: " + e.getMessage());
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
			EncryptedToken token, ArrayList<GroupKeyList> groupKeys) {

		if (destFile.charAt(0)!='/') {
			 destFile = "/" + destFile;
		 }

		try
		 {
			 //Get the group key to send its hash to the server
			 //Uses most recent group key to encrypt a file
			 Key groupKey = null;
			 for(int i = 0; i < groupKeys.size(); i++){
				 if(groupKeys.get(i).getName().compareTo(group) == 0){
					 groupKey = groupKeys.get(i).getEncrypterKey();
					 break;
				 }
			 }
			 //Sanity check
			 if(groupKey == null){
				 System.out.println(">>>Error: Could not find group in list");
				 return false;
			 }

		 	//Encrypt Everything
		 	AESEncrypter destEnc = new AESEncrypter(AESKey);
		 	AESEncrypter groupEnc = new AESEncrypter(AESKey);
			AESEncrypter hashEnc = new AESEncrypter(AESKey);

		 	EncryptedMessage dest = destEnc.encrypt(destFile);
		 	EncryptedMessage _group = groupEnc.encrypt(group);
			byte[] keyedHash = getKeyedHash(groupKey);
			EncryptedMessage encKeyedHash = hashEnc.encrypt(keyedHash);

			//Read in entire file
			byte[] fileBytes = new byte[1];
			try{
				FileInputStream fis = new FileInputStream(sourceFile);
				fileBytes = new byte[fis.available()];
				fis.read(fileBytes);
				fis.close();
			} catch(Exception ex){
				System.out.println("Upload Failed. File either does not exist or another error has occured");
				//ex.printStackTrace();
				return false;
			}

			Envelope message = null, env = null;
			//Tell the server to return the member list
			message = new Envelope("UPLOADF");
			message.addObject(dest);
			message.addObject(_group);
			message.addObject(token); //Add requester's token
			message.addObject(encKeyedHash); //Add hash of group's key
			//Add increment value
			EncryptedMessage increment = increment();
			message.addObject(increment);

			output.writeObject(message);

			env = (Envelope)input.readObject();

			//If server indicates success, return the member list
			if(env.getMessage().equals("READY"))
			{
				System.out.printf("Meta data upload successful\n");
			}
			else {
				System.out.printf("Upload failed: %s\n", env.getMessage());
				//Check increment value
				EncryptedMessage incrementIn = (EncryptedMessage)env.getObjContents().get(0);
				if(!checkIncrement(incrementIn)){
					System.out.println("Client Replay detected");
					System.exit(0);
				}
				return false;
			}

			//Encrypt the file using group key
			AESEncrypter fileEnc = new AESEncrypter(groupKey);
			EncryptedMessage encFile = fileEnc.encrypt(fileBytes);

			//Get byte[]'s for the encFile object
			byte[] ivBytes = encFile.getIVBytes();
			byte[] encFileBytes = encFile.getEncryptedBytes();

			byte[] encodedBytes = Base64.getEncoder().encode(encFileBytes);


			//Put into new byte array: [ivBytes, encFileBytes]
			int sizeToSend = ivBytes.length + encodedBytes.length;

			byte[] toSend = new byte[sizeToSend];
			int i;
			for(i = 0; i < ivBytes.length; i++){
				toSend[i] = ivBytes[i];
			}
			// toSend[i++] = ((byte)'|');
			for(int k = 0; k < encodedBytes.length; k++){
				toSend[i++] = encodedBytes[k];
			}

			int t = 0;
			do {
				byte[] buf = new byte[4096];
			 	if (env.getMessage().compareTo("READY")!=0) {
			 		System.out.printf("Server error: %s\n", env.getMessage());
			 		return false;
			 	}
			 	message = new Envelope("CHUNK");

			 	//Populate buf
			 	for(i = 0; i < buf.length; i++){
			 		if(t == toSend.length){
			 			break;
			 		}
			 		buf[i] = toSend[t++];
			 		System.out.printf(".");
			 	}

				message.addObject(buf);
				message.addObject(new Integer(i));

				output.writeObject(message);


				env = (Envelope)input.readObject();


			 }
			 while (t < toSend.length);

			 //If server indicates success, return the member list
			 if(env.getMessage().compareTo("READY")==0)
			 {

				message = new Envelope("EOF");
				output.writeObject(message);

				env = (Envelope)input.readObject();

				if(env.getMessage().compareTo("OK")==0) {
					System.out.printf("\nFile data upload successful\n");
					//Check increment value
					EncryptedMessage incrementIn = (EncryptedMessage)env.getObjContents().get(0);
					if(!checkIncrement(incrementIn)){
						System.out.println("Client Replay detected");
						System.exit(0);
					}
				}
				else {
					 System.out.printf("\nUpload failed: %s\n", env.getMessage());
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

	//Diffie-Hellman exchange to create shared AES session key
	public BigInteger performDiffie(BigInteger p, BigInteger g, BigInteger C)
	 {
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

	 private byte[] getKeyedHash(Key groupkey) {
		 byte[] gKeyHash = null;
		 try {
			 	DigestSHA3 md = new DigestSHA3(256);
				md.update(groupkey.getEncoded());
			 	gKeyHash = md.digest();
		 } catch(Exception ex) {
			 ex.printStackTrace();
		 }
		 return gKeyHash;
	 }
}
