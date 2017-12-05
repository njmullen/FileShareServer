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

		byte[] y = null;
		try {
			DigestSHA3 md = new DigestSHA3(256);
			md.update(x);
			y = md.digest();
		} catch(Exception ex) {
			ex.printStackTrace();
		}

		byte[] z = null;
		try {
			DigestSHA3 md = new DigestSHA3(256);
			md.update(y);
			z = md.digest();
		} catch(Exception ex) {
			ex.printStackTrace();
		}

		BitSet yBit = new BitSet();
		yBit = yBit.valueOf(y);

		for (int i = 254; i > 231; i--){
			yBit.set(i, false);
		}

		PuzzleSolver pz = new PuzzleSolver();
		byte[] yRet = pz.solve24BitPuzzle(yBit, z);
	}
}