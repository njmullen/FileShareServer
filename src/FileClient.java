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

	public void setAESKey(Key key){
		AESKey = key;
		//Decrypt the increment value
		AESDecrypter valDecr = new AESDecrypter(AESKey);
		incrementVal = valDecr.decryptInt(encryptedVal);
		System.out.println("CLIENT" + incrementVal);
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

	public boolean download(String sourceFile, String destFile, EncryptedToken token, ArrayList<GroupKey> groupKeys) {
		if (sourceFile.charAt(0)=='/') {
			sourceFile = sourceFile.substring(1);
		}

		File file = new File(destFile);
	    try {
		    	file.createNewFile();
			    FileOutputStream fos = new FileOutputStream(file);

			    Envelope env = new Envelope("DOWNLOADF"); //Success

			    AESEncrypter fileEnc = new AESEncrypter(AESKey);
			    EncryptedMessage sourceEnc = fileEnc.encrypt(sourceFile);
			    env.addObject(sourceEnc);
			    env.addObject(token);
			    output.writeObject(env);

			    env = (Envelope)input.readObject();

			    String group = null;

			    //Receive the group from the server
				if(env.getMessage().compareTo("GROUP") == 0){
					AESDecrypter groupDec = new AESDecrypter(AESKey);
					group = groupDec.decrypt((EncryptedMessage)env.getObjContents().get(0));
				}
				else{
					System.out.printf("Error: Could not retrieve group for file\n");
					System.out.printf("Message contents: %s\n", env.getMessage());
				}

				//Grab group key from list
				//Have to figure out how we'll hash keys and deal with multiple old keys
				SecretKey groupKey = null;
				for(int i = 0; i < groupKeys.size(); i++){
					if(groupKeys.get(i).getName().compareTo(group) == 0){
						groupKey = groupKeys.get(i).getKey();
						break;
					}
				}

				env = (Envelope)input.readObject();

			    //TODO: Ensure bounds
			    //Read in IvSpec and entire encrypted file
			    boolean readingSize = true;
			    boolean readingIV = false;
			    byte[] ivBytes = new byte[1];
			    int ivSize = 0;
			    StringBuilder encFileSb = new StringBuilder();
				while (env.getMessage().compareTo("CHUNK")==0) {
					byte[] bytesIn = (byte[])env.getObjContents().get(0);
					int messageSize = (Integer)env.getObjContents().get(1);
					int ind = 0;

					//TROUBLESHOOTING
					System.out.println("\n\n>>>>>CHUNK:");
					System.out.println(">>>messageSize = " + messageSize);
					System.out.println(">>>bytesIn = " + new String(bytesIn));

					//Check if reading size of IVSpec
					if(readingSize){
						//Parse the size of the IVSpec
						StringBuilder sizeSB = new StringBuilder();
						int i = 0;
						while((char)bytesIn[i] != '|'){
							sizeSB.append((char)bytesIn[i++]);
						}
						ind = ++i;
						ivSize = new Integer(sizeSB.toString());

						//TROUBLESHOOTING
						System.out.println(">>>ivSize = " + ivSize);

						readingSize = false;
						readingIV = true;
					}
					//Check if reading the IVSpec
					if(readingIV){

						//TROUBLESHOOTING
						System.out.println(">>>>Reading IV:");

						ivBytes = new byte[ivSize];
						for(int i = 0; i < ivSize; i++){
							ivBytes[i] = bytesIn[ind++];
							
							//TROUBLESHOOTING
							System.out.println("ivBytes[" + i + "] = " + (char)ivBytes[i]);
						}

						//TROUBLESHOOTING
						System.out.println("\n");

						readingIV = false;
						messageSize -= ind;

						//TROUBLESHOOTING
						System.out.println(">>>ind = " + ind);
						System.out.println(">>>messageSize = " + messageSize);
					}

					//TROUBLESHOOTING
					System.out.println(">>>>Reading Message Chunk:");
					while(ind < messageSize){
						encFileSb.append((char)bytesIn[ind++]);

						//TROUBLESHOOTING
						System.out.println(">>>encFileSb = " + encFileSb.toString());
					}

					//TROUBLESHOOTING
					System.out.println("\n");


					//fos.write((byte[])env.getObjContents().get(0), 0, (Integer)env.getObjContents().get(1));

					System.out.printf(".");
					env = new Envelope("DOWNLOADF"); //Success
					output.writeObject(env);
					env = (Envelope)input.readObject();
				}

				//Decrypt and write the file
				byte[] encFileBytes = encFileSb.toString().getBytes();
				IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
				EncryptedMessage encFile = new EncryptedMessage(encFileBytes, ivSpec);


				// //TROUBLESHOOTING
				// System.out.println(">>>encFileBytes = " + new String(encFileBytes));
				// System.out.println(">>>ivSpec = " + new String(ivSpec.getIV()));

				AESDecrypter fileDec = new AESDecrypter(groupKey);
				byte[] decFileBytes = fileDec.decryptBytes(encFile);

				// //TROUBLESHOOTING
				// System.out.println(new String(decFileBytes));

				fos.write(decFileBytes);
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
			 output.writeObject(message);

			 e = (Envelope)input.readObject();


			 //If server indicates success, return the member list
			 if(e.getMessage().equals("OK"))
			 {
				int size = (int)e.getObjContents().get(0);
				List<String> fileList = new ArrayList<String>();
				for(int i = 1; i < size + 1; i++){
			 		EncryptedMessage encList = (EncryptedMessage)e.getObjContents().get(i);
			 		AESDecrypter listDecr = new AESDecrypter(AESKey);
			 		String thisMember = listDecr.decrypt(encList);
			 		fileList.add(thisMember);
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

	public boolean upload(String sourceFile, String destFile, String group,
			EncryptedToken token, ArrayList<GroupKey> groupKeys) {

		if (destFile.charAt(0)!='/') {
			 destFile = "/" + destFile;
		 }

		try
		 {

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
			output.writeObject(message);

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

			//Read in entire file
			byte[] fileBytes = new byte[1];
			try{
				FileInputStream fis = new FileInputStream(sourceFile);
				fileBytes = new byte[fis.available()];
				fis.read(fileBytes);
				fis.close();
			}
			catch(Exception ex){
				ex.printStackTrace();
			}

			//TODO: Use most recent key for group, not just any key related to group
			//Find group key in list
			//Finds first Group key then encrypts with it.
			SecretKey groupKey = null;
			for(int i = 0; i < groupKeys.size(); i++){
				if(groupKeys.get(i).getName().compareTo(group) == 0){
					groupKey = groupKeys.get(i).getKey();
					break;
				}
			}
			//Sanity check
			if(groupKey == null){
				System.out.println(">>>Error: Could not find group in list");
				return false;
			}

			//Encrypt the file using group key
			AESEncrypter fileEnc = new AESEncrypter(groupKey);
			EncryptedMessage encFile = fileEnc.encrypt(fileBytes);

			//Get byte[]'s for the encFile object
			byte[] ivBytes = encFile.getIVBytes();
			byte[] encFileBytes = encFile.getEncryptedBytes();
			byte[] ivSizeBytes = new Integer(ivBytes.length).toString().getBytes();

			//TROUBLESHOOTING
			System.out.println("\n\n>>>>>UPLOAD:");
			System.out.println(">>>ivBytes = " + new String(ivBytes));
			System.out.println(">>>encFileBytes = " + new String(encFileBytes));
			System.out.println("\n");


			//Put into new byte array: [size of IV, |, ivBytes, encFileBytes]
			int sizeToSend = ivSizeBytes.length + ivBytes.length + encFileBytes.length + 1;
			byte[] toSend = new byte[sizeToSend];
			int i;
			for(i = 0; i < ivSizeBytes.length; i++){
				toSend[i] = ivSizeBytes[i];
			}
			toSend[i++] = ((byte)'|');
			for(int j = 0; j < ivBytes.length; j++){
				toSend[i++] = ivBytes[j];
			}
			for(int k = 0; k < encFileBytes.length; k++){
				toSend[i++] = encFileBytes[k];
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

				// int n = fis.read(buf); //can throw an IOException
				// if (n > 0) {
				// 	System.out.printf(".");
				// } else if (n < 0) {
				// 	System.out.println("Read error");
				// 	return false;
				// }

				// //????????????????
				// AESEncrypter bufEnc = new AESEncrypter(groupKey);

				// EncryptedMessage bufSend = bufEnc.encrypt(buf);

				message.addObject(buf);
				message.addObject(new Integer(i + 1));

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
				BigInteger S = (BigInteger)response.getObjContents().get(0);
				//Grabs the encrypted increment value which will be decrypted
				//once the client calculates the shared AES key
				encryptedVal = (EncryptedMessage)response.getObjContents().get(1);
				return S;
			}
			return null;
	 	} catch (Exception ex){
	 		ex.printStackTrace();
	 	}

	 	return null;
	 }


}
