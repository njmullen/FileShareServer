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

public class HashInversion {
	

	public static void main(String[] args){

		Security.addProvider(new BouncyCastleProvider());
		BigInteger b = new BigInteger(128, new Random());
		byte[] x = b.toByteArray();
		System.out.println("B: " + b);

		//Hash x to get y
		byte[] y = null;
		try {
			DigestSHA3 md = new DigestSHA3(256);
			md.update(x);
			y = md.digest();
		} catch(Exception ex) {
			ex.printStackTrace();
		}

		System.out.println("y: ");
		for (int i = 0; i < y.length; i++){
			System.out.println("y(" + i + "): " + y[i]);
		}
		System.out.println("");

		//Hash y to get z
		byte[] z = null;
		try {
			DigestSHA3 md = new DigestSHA3(256);
			md.update(y);
			z = md.digest();
		} catch(Exception ex) {
			ex.printStackTrace();
		}

		System.out.println("z: ");
		for (int i = 0; i < z.length; i++){
			System.out.println("z(" + i + "): " + z[i]);
		}
		System.out.println("");

		//Cut last 2 digits of y
		byte[] yPrime = new byte[28];
		for (int i = 0; i < 28; i++){
			yPrime[i] = y[i];
		}

		System.out.println("yPrime: ");
		for (int i = 0; i < yPrime.length; i++){
			System.out.println("y'(" + i + "): " + yPrime[i]);
		}
		System.out.println("");

		//Guess last 4 bits of yPrime, hash and compare to z
		//HAS to be a better way to do this

		//Convert yPrime to 32 bit array
		//Cut last 2 digits of y
		byte[] yFinal = new byte[32];
		for (int i = 0; i < 28; i++){
			yFinal[i] = yPrime[i];
		}
		yFinal[28] = 0;
		yFinal[29] = 0;
		yFinal[30] = 0;
		yFinal[31] = 0;

		byte i = -127;
		byte j = -127;
		byte k = -127;
		byte l = -127;

		long startTime = System.nanoTime();

		while (i <= 127){
			System.out.println(i);
			while (j <= 127){
				while (k <= 127){
					while (l <= 127){
						yFinal[28] = i;
						yFinal[29] = j;
						yFinal[30] = k;
						yFinal[31] = l;

						//Hash yFinal to check with z
						byte[] zCheck = null;
						try {
							DigestSHA3 md = new DigestSHA3(256);
							md.update(yFinal);
							zCheck = md.digest();
						} catch(Exception ex) {
							ex.printStackTrace();
						}

						if(Arrays.equals(zCheck, z)){
							long endTime = System.nanoTime();
							System.out.println(endTime - startTime);
							System.out.println("Match");
							System.exit(0);
						}

						l++;
						if (l == -128){
							break;
						}
					}
					k++;
					if (k == -128){
						break;
					}
				}
				j++;
				if (j == -128){
					break;
				}
			}
			i++;
			if (i == -128){
				break;
			}
		}


	}



}