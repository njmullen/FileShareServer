import org.bouncycastle.jce.provider.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;


public class DiffieDemo {

	public static void main(String[] args){
		//Initialize a parameter generator for Diffie-Hellman and initialize it to 1024-bits
		Security.addProvider(new BouncyCastleProvider());
		DHParameterSpec dhSpec = null;
		try {
			AlgorithmParameterGenerator dhGenerator = AlgorithmParameterGenerator.getInstance("DH");
			dhGenerator.init(1024, new SecureRandom());
			AlgorithmParameters dhParameters = dhGenerator.generateParameters();
			dhSpec = (DHParameterSpec)dhParameters.getParameterSpec(DHParameterSpec.class);
		} catch (Exception ex){
			ex.printStackTrace();
		}

		Random random = new Random();

		//s = the secret number that the server generates
		//p = the prime number 
		//g = prime number generator 
		//S = the calculated half key of the server (g^s mod p)
		BigInteger s = new BigInteger(1024, random);
		BigInteger p = dhSpec.getP();
		BigInteger g = dhSpec.getG();
		BigInteger S = g.modPow(s, p);

		//Server then sends S, p, g to user

		//User recieves S, p, g

		//c = the secret number that the client generates
		//C = the calculated half key of the client (g^c mod p)
		BigInteger c = new BigInteger(1024, random);
		BigInteger C = g.modPow(c, p);

		//Calculate server key using the C from the client with s and p
		//Calculate client key using the S fromt he server with c and p
		BigInteger serverKey = C.modPow(s, p);
		BigInteger clientKey = S.modPow(c, p);

		//Generate an AES key using the first 16 bits of the DH key
		byte[] serverByteKey = serverKey.toByteArray();
		byte[] clientByteKey = clientKey.toByteArray();
		byte[] serverBytes = new byte[16];
		byte[] clientBytes = new byte[16];

		for (int i = 0; i < 16; i++){
			serverBytes[i] = serverByteKey[i];
			clientBytes[i] = clientByteKey[i];
		}

		//Generates two AES keys
		Key serverAESKey = null;
		Key clientAESKey = null;
		try {
			serverAESKey = new SecretKeySpec(serverBytes, "AES");
			clientAESKey = new SecretKeySpec(clientBytes, "AES");
		} catch (Exception ex) {
			ex.printStackTrace();
		}

		String mainString = "The quick brown fox jumps over the lazy dog";
		byte[] stringToEncrypt = mainString.getBytes();

		//Generate byte arrays for holding encrypted/decrypted text and an IVSpec
		byte[] encrytedServerText = null;
		byte[] decryptedClientText = null;
		IvParameterSpec AESIVSpec = new IvParameterSpec(new byte[16]);

		//Simulate encryption with the server key and decryption with the client key
		try {
			Cipher AESEncryptCipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
			AESEncryptCipher.init(Cipher.ENCRYPT_MODE, serverAESKey, AESIVSpec);
			encrytedServerText = AESEncryptCipher.doFinal(stringToEncrypt);

			Cipher AESDecryptCipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
			AESDecryptCipher.init(Cipher.DECRYPT_MODE, clientAESKey, AESIVSpec);
			decryptedClientText = AESDecryptCipher.doFinal(encrytedServerText);
		} catch (Exception ex){
			ex.printStackTrace();
		}

		String decryptedPlainText = new String(decryptedClientText);
		System.out.println(decryptedPlainText);
	}


}