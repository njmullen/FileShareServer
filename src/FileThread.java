/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import java.lang.Thread;
import java.net.Socket;
import java.util.List;
import java.util.ArrayList;
import java.util.Random;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

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

public class FileThread extends Thread
{
	private final Socket socket;
	private BigInteger dhKey = null;
	private Key AESKey = null;
	private PublicKey groupServerKey = null;

	public FileThread(Socket _socket)
	{
		socket = _socket;
	}

	public void run()
	{
		boolean proceed = true;
		try
		{
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			Envelope response;

			do
			{
				Envelope e = (Envelope)input.readObject();
				System.out.println("Request received: " + e.getMessage());

				// Handler to list files that this user is allowed to see
				if(e.getMessage().equals("LFILES"))
				{
				    if(e.getObjContents().size() != 1){
				    	response = new Envelope("FAIL-BADCONTENTS");
				    }
				    else{
				    	if(e.getObjContents().get(0) == null){
				    		response = new Envelope("FAIL-BADTOKEN");
				    	}
				    	else{
				    		UserToken yourToken = (UserToken)e.getObjContents().get(0);
				    		ArrayList<ShareFile> fullList = new ArrayList<ShareFile>(FileServer.fileList.getFiles()); //Pull full list from file server
				    		List<String> accessList = new ArrayList<String>(); //Stores names of files which user has access to
				    		
				    		//Check all files on server and compile list of files which user can access
				    		ShareFile currFile;
				    		while(!fullList.isEmpty()){
				    			currFile = fullList.remove(0);
				    			String fGroup = currFile.getGroup();
				    			if(yourToken.getGroups().contains(fGroup)){
				    				accessList.add(currFile.getPath());
				    			}
				    		}

				    		System.out.printf("Successfully generated file list\n");
				    		response = new Envelope("OK"); //Success
				    		response.addObject(accessList);
				    		
				    		output.writeObject(response);
				    	}
				    }
				}
				if(e.getMessage().equals("UPLOADF"))
				{

					if(e.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL-BADCONTENTS");
					}
					else
					{
						if(e.getObjContents().get(0) == null) {
							response = new Envelope("FAIL-BADPATH");
						}
						if(e.getObjContents().get(1) == null) {
							response = new Envelope("FAIL-BADGROUP");
						}
						if(e.getObjContents().get(2) == null) {
							response = new Envelope("FAIL-BADTOKEN");
						}
						else {

							EncryptedMessage encPat = (EncryptedMessage)e.getObjContents().get(0);
							EncryptedMessage groupPat = (EncryptedMessage)e.getObjContents().get(1);
							EncryptedToken encTok = (EncryptedToken)e.getObjContents().get(2);

							AESDecrypter patDec = new AESDecrypter(AESKey);
							AESDecrypter groupDec = new AESDecrypter(AESKey);
							AESDecrypter tokDec = new AESDecrypter(AESKey);
							AESDecrypter sigDec = new AESDecrypter(AESKey);

							String remotePath = patDec.decrypt(encPat);
							String group = groupDec.decrypt(groupPat);

							byte[] tokBytes = tokDec.decryptBytes(encTok.getToken());
							byte[] sigBytes = sigDec.decryptBytes(encTok.getSignature());

							if(!verifySig(tokBytes, sigBytes)){
								System.out.printf("INVALID SIGNATURE!");
								System.exit(0);
							}

							Token yourToken = new Token(tokBytes);

							if (FileServer.fileList.checkFile(remotePath)) {
								System.out.printf("Error: file already exists at %s\n", remotePath);
								response = new Envelope("FAIL-FILEEXISTS"); //Success
							}
							else if (!yourToken.getGroups().contains(group)) {
								System.out.printf("Error: user missing valid token for group %s\n", group);
								response = new Envelope("FAIL-UNAUTHORIZED"); //Success
							}
							else  {
								File file = new File("shared_files/"+remotePath.replace('/', '_'));
								file.createNewFile();
								FileOutputStream fos = new FileOutputStream(file);
								System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));

								response = new Envelope("READY"); //Success
								output.writeObject(response);

								e = (Envelope)input.readObject();
								while (e.getMessage().compareTo("CHUNK")==0) {

									EncryptedMessage encBuf = (EncryptedMessage)e.getObjContents().get(0);

									AESDecrypter decBuf = new AESDecrypter(AESKey);

									fos.write(decBuf.decryptBytes(encBuf), 0, (Integer)e.getObjContents().get(1));
									response = new Envelope("READY"); //Success
									output.writeObject(response);
									e = (Envelope)input.readObject();
								}

								if(e.getMessage().compareTo("EOF")==0) {
									System.out.printf("Transfer successful file %s\n", remotePath);
									FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath);
									response = new Envelope("OK"); //Success
								}
								else {
									System.out.printf("Error reading file %s from client\n", remotePath);
									response = new Envelope("ERROR-TRANSFER"); //Success
								}
								fos.close();
							}
						}
					}

					output.writeObject(response);
				}
				else if (e.getMessage().compareTo("DOWNLOADF")==0) {

					AESDecrypter aesDec = new AESDecrypter(AESKey);

					EncryptedMessage encRemPat = (EncryptedMessage)e.getObjContents().get(0);
					EncryptedMessage encTok = (EncryptedMessage)e.getObjContents().get(1);

					byte[] tokBytes = aesDec.decryptBytes(encTok);
					String remotePath = aesDec.decrypt(encRemPat);

					Token t = new Token(tokBytes);
					

					
					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR_FILEMISSING");
						output.writeObject(e);

					}
					else if (!t.getGroups().contains(sf.getGroup())){
						System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
						e = new Envelope("ERROR_PERMISSION");
						output.writeObject(e);
					}
					else {

						try
						{
							File f = new File("shared_files/_"+remotePath.replace('/', '_'));
						if (!f.exists()) {
							System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
							e = new Envelope("ERROR_NOTONDISK");
							output.writeObject(e);

						}
						else {
							FileInputStream fis = new FileInputStream(f);

							do {
								byte[] buf = new byte[4096];
								if (e.getMessage().compareTo("DOWNLOADF")!=0) {
									System.out.printf("Server error: %s\n", e.getMessage());
									break;
								}
								e = new Envelope("CHUNK");
								int n = fis.read(buf); //can throw an IOException
								if (n > 0) {
									System.out.printf(".");
								} else if (n < 0) {
									System.out.println("Read error");

								}


								e.addObject(buf);
								e.addObject(new Integer(n));

								output.writeObject(e);

								e = (Envelope)input.readObject();


							}
							while (fis.available()>0);

							//If server indicates success, return the member list
							if(e.getMessage().compareTo("DOWNLOADF")==0)
							{

								e = new Envelope("EOF");
								output.writeObject(e);

								e = (Envelope)input.readObject();
								if(e.getMessage().compareTo("OK")==0) {
									System.out.printf("File data upload successful\n");
								}
								else {

									System.out.printf("Upload failed: %s\n", e.getMessage());

								}

							}
							else {

								System.out.printf("Upload failed: %s\n", e.getMessage());

							}
						}
						}
						catch(Exception e1)
						{
							System.err.println("Error: " + e.getMessage());
							e1.printStackTrace(System.err);

						}
					}
				}
				else if (e.getMessage().compareTo("DELETEF")==0) {

					EncryptedMessage encRemPat = (EncryptedMessage)e.getObjContents().get(0);
					EncryptedToken encTok = (EncryptedToken)e.getObjContents().get(1);

					
					//Decrypt everything
					AESDecrypter remDec = new AESDecrypter(AESKey);
					String remotePath = remDec.decrypt(encRemPat);

					AESDecrypter tokDec = new AESDecrypter(AESKey);
					byte[] tokenBytes = tokDec.decryptBytes(encTok.getToken());

					AESDecrypter sigDec = new AESDecrypter(AESKey);
					byte[] sigBytes = sigDec.decryptBytes(encTok.getSignature());


					if(verifySig(tokenBytes, sigBytes)){
						Token t = new Token(tokenBytes);
						ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
						if (sf == null) {
							System.out.printf("Error: File %s doesn't exist\n", remotePath);
							e = new Envelope("ERROR_DOESNTEXIST");
						}
						else if (!t.getGroups().contains(sf.getGroup())){
							System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
							e = new Envelope("ERROR_PERMISSION");
						}
						else {
							try
							{
								File f = new File("shared_files/"+"_"+remotePath.replace('/', '_'));
								if (!f.exists()) {
									System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
									e = new Envelope("ERROR_FILEMISSING");
								}
								else if (f.delete()) {
									System.out.printf("File %s deleted from disk\n", "_"+remotePath.replace('/', '_'));
									FileServer.fileList.removeFile("/"+remotePath);
									e = new Envelope("OK");
								}
								else {
									System.out.printf("Error deleting file %s from disk\n", "_"+remotePath.replace('/', '_'));
									e = new Envelope("ERROR_DELETE");
								}
							}
							catch(Exception e1)
							{
								System.err.println("Error: " + e1.getMessage());
								e1.printStackTrace(System.err);
								e = new Envelope(e1.getMessage());
							}
						}
					}
					else{
						e = new Envelope("FAIL!! UNABLE TO VERIFY SIGNATURE");
					}

					
					output.writeObject(e);

				}

				//Client wants to send GroupServer key
				else if (e.getMessage().compareTo("GK") == 0){
					if(e.getObjContents().size() != 1){
						response = new Envelope("FAIL-BADCONTENTS");
					}
					else{
						groupServerKey = (PublicKey)e.getObjContents().get(0);
						response = new Envelope("OK");
					}

					output.writeObject(response);
				}

				//Client wants to do DH Exchange
				else if (e.getMessage().compareTo("DH") == 0){
					if(e.getObjContents().size() < 3){
						response = new Envelope("FAIL-BADCONTENTS");
					}

					BigInteger p = (BigInteger)e.getObjContents().get(0);
					BigInteger g = (BigInteger)e.getObjContents().get(1);
					BigInteger C = (BigInteger)e.getObjContents().get(2);

					Random random = new Random();
				 	BigInteger s = new BigInteger(1024, random);
				 	BigInteger S = g.modPow(s, p);
				 	dhKey = C.modPow(s, p);


				 	//Create AESKey
				 	byte[] dhKeyBytes = dhKey.toByteArray();
				 	byte[] shortBytes = new byte[16];

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
				}


				else if(e.getMessage().equals("DISCONNECT"))
				{
					socket.close();
					proceed = false;
				}
			} while(proceed);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}

	private boolean verifySig(byte[] tokenBytes, byte[] sigBytes){
		try{
			Signature signature = Signature.getInstance("RSA");
			signature.initVerify(groupServerKey);
			signature.update(tokenBytes);
			if (signature.verify(sigBytes)){
				return true;
			} else {
				return false;
			}
		}
		catch(Exception ex){
			ex.printStackTrace();
		}
		return false;
		
	}

}
