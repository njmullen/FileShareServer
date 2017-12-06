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

public class PuzzleSolver {

	//Takes ~0.2s
	public byte[] solve16BitPuzzle(BitSet yPrime, byte[] z){
		Security.addProvider(new BouncyCastleProvider());
		long startTime = System.nanoTime();

		for(int a = 0; a <= 1; a++){
		for(int b = 0; b <= 1; b++){
		for(int c = 0; c <= 1; c++){
		for(int d = 0; d <= 1; d++){
		for(int e = 0; e <= 1; e++){
		for(int f = 0; f <= 1; f++){
		for(int g = 0; g <= 1; g++){
		for(int h = 0; h <= 1; h++){
		for(int i = 0; i <= 1; i++){
		for(int j = 0; j <= 1; j++){
		for(int k = 0; k <= 1; k++){
		for(int l = 0; l <= 1; l++){
		for(int m = 0; m <= 1; m++){
		for(int n = 0; n <= 1; n++){
		for(int o = 0; o <= 1; o++){
		for(int p = 0; p <= 1; p++){
			//Set the bits to be true if 0, false if 1
			boolean aFlip = (a == 0);
			boolean bFlip = (b == 0);
			boolean cFlip = (c == 0);
			boolean dFlip = (d == 0);
			boolean eFlip = (e == 0);
			boolean fFlip = (f == 0);
			boolean gFlip = (g == 0);
			boolean hFlip = (h == 0);
			boolean iFlip = (i == 0);
			boolean jFlip = (j == 0);
			boolean kFlip = (k == 0);
			boolean lFlip = (l == 0);
			boolean mFlip = (m == 0);
			boolean nFlip = (n == 0);
			boolean oFlip = (o == 0);
			boolean pFlip = (p == 0);

			//Actually sets the bits
			yPrime.set(254, aFlip);
			yPrime.set(253, bFlip);
			yPrime.set(252, cFlip);
			yPrime.set(251, dFlip);
			yPrime.set(250, eFlip);
			yPrime.set(249, fFlip);
			yPrime.set(248, gFlip);
			yPrime.set(247, hFlip);
			yPrime.set(246, iFlip);
			yPrime.set(245, jFlip);
			yPrime.set(244, kFlip);
			yPrime.set(243, lFlip);
			yPrime.set(242, mFlip);
			yPrime.set(241, nFlip);
			yPrime.set(240, oFlip);
			yPrime.set(239, pFlip);

			//Convert to byte array and cmopare hash to z
			byte[] yPrimeByte = yPrime.toByteArray();
			byte[] yHashed = null;
			try {
				DigestSHA3 md = new DigestSHA3(256);
				md.update(yPrimeByte);
				yHashed = md.digest();
			} catch(Exception ex) {
				ex.printStackTrace();
			}

			//If hash matches z, return yHashed
			if(Arrays.equals(yHashed, z)){
				return yPrimeByte;
			}
		}
		}
		}
		}
		}
		}
		}
		}
		}
		}
		}
		}
		}
		}
		}
		}
		return null;
	}

	//Takes ~1.5-2seconds
	public byte[] solve20BitPuzzle(BitSet yPrime, byte[] z){
		Security.addProvider(new BouncyCastleProvider());
		long startTime = System.nanoTime();
		
		for(int a = 0; a <= 1; a++){
		for(int b = 0; b <= 1; b++){
		for(int c = 0; c <= 1; c++){
		for(int d = 0; d <= 1; d++){
		for(int e = 0; e <= 1; e++){
		for(int f = 0; f <= 1; f++){
		for(int g = 0; g <= 1; g++){
		for(int h = 0; h <= 1; h++){
		for(int i = 0; i <= 1; i++){
		for(int j = 0; j <= 1; j++){
		for(int k = 0; k <= 1; k++){
		for(int l = 0; l <= 1; l++){
		for(int m = 0; m <= 1; m++){
		for(int n = 0; n <= 1; n++){
		for(int o = 0; o <= 1; o++){
		for(int p = 0; p <= 1; p++){
		for(int q = 0; q <= 1; q++){
		for(int r = 0; r <= 1; r++){
		for(int s = 0; s <= 1; s++){
		for(int t = 0; t <= 1; t++){
			//Set the bits to be true if 0, false if 1
			boolean aFlip = (a == 0);
			boolean bFlip = (b == 0);
			boolean cFlip = (c == 0);
			boolean dFlip = (d == 0);
			boolean eFlip = (e == 0);
			boolean fFlip = (f == 0);
			boolean gFlip = (g == 0);
			boolean hFlip = (h == 0);
			boolean iFlip = (i == 0);
			boolean jFlip = (j == 0);
			boolean kFlip = (k == 0);
			boolean lFlip = (l == 0);
			boolean mFlip = (m == 0);
			boolean nFlip = (n == 0);
			boolean oFlip = (o == 0);
			boolean pFlip = (p == 0);
			boolean qFlip = (q == 0);
			boolean rFlip = (r == 0);
			boolean sFlip = (s == 0);
			boolean tFlip = (t == 0);

			//Actually sets the bits
			yPrime.set(254, aFlip);
			yPrime.set(253, bFlip);
			yPrime.set(252, cFlip);
			yPrime.set(251, dFlip);
			yPrime.set(250, eFlip);
			yPrime.set(249, fFlip);
			yPrime.set(248, gFlip);
			yPrime.set(247, hFlip);
			yPrime.set(246, iFlip);
			yPrime.set(245, jFlip);
			yPrime.set(244, kFlip);
			yPrime.set(243, lFlip);
			yPrime.set(242, mFlip);
			yPrime.set(241, nFlip);
			yPrime.set(240, oFlip);
			yPrime.set(239, pFlip);
			yPrime.set(238, qFlip);
			yPrime.set(237, rFlip);
			yPrime.set(236, sFlip);
			yPrime.set(235, tFlip);

			//Convert to byte array and cmopare hash to z
			byte[] yPrimeByte = yPrime.toByteArray();
			byte[] yHashed = null;
			try {
				DigestSHA3 md = new DigestSHA3(256);
				md.update(yPrimeByte);
				yHashed = md.digest();
			} catch(Exception ex) {
				ex.printStackTrace();
			}

			//If hash matches z, return yHashed
			if(Arrays.equals(yHashed, z)){
				return yPrimeByte;
			}
		}
		}
		}
		}
		}
		}
		}
		}
		}
		}
		}
		}
		}
		}
		}
		}
		}
		}
		}
		}
		return null;
	}

	//Takes ~11-20seconds
	public byte[] solve24BitPuzzle(BitSet yPrime, byte[] z){
		Security.addProvider(new BouncyCastleProvider());
		long startTime = System.nanoTime();
		
		for(int a = 0; a <= 1; a++){
		for(int b = 0; b <= 1; b++){
		for(int c = 0; c <= 1; c++){
		for(int d = 0; d <= 1; d++){
		for(int e = 0; e <= 1; e++){
		for(int f = 0; f <= 1; f++){
		for(int g = 0; g <= 1; g++){
		for(int h = 0; h <= 1; h++){
		for(int i = 0; i <= 1; i++){
		for(int j = 0; j <= 1; j++){
		for(int k = 0; k <= 1; k++){
		for(int l = 0; l <= 1; l++){
		for(int m = 0; m <= 1; m++){
		for(int n = 0; n <= 1; n++){
		for(int o = 0; o <= 1; o++){
		for(int p = 0; p <= 1; p++){
		for(int q = 0; q <= 1; q++){
		for(int r = 0; r <= 1; r++){
		for(int s = 0; s <= 1; s++){
		for(int t = 0; t <= 1; t++){
		for(int u = 0; u <= 1; u++){
		for(int v = 0; v <= 1; v++){
		for(int w = 0; w <= 1; w++){
		for(int x = 0; x <= 1; x++){
			//Set the bits to be true if 0, false if 1
			boolean aFlip = (a == 0);
			boolean bFlip = (b == 0);
			boolean cFlip = (c == 0);
			boolean dFlip = (d == 0);
			boolean eFlip = (e == 0);
			boolean fFlip = (f == 0);
			boolean gFlip = (g == 0);
			boolean hFlip = (h == 0);
			boolean iFlip = (i == 0);
			boolean jFlip = (j == 0);
			boolean kFlip = (k == 0);
			boolean lFlip = (l == 0);
			boolean mFlip = (m == 0);
			boolean nFlip = (n == 0);
			boolean oFlip = (o == 0);
			boolean pFlip = (p == 0);
			boolean qFlip = (q == 0);
			boolean rFlip = (r == 0);
			boolean sFlip = (s == 0);
			boolean tFlip = (t == 0);
			boolean uFlip = (u == 0);
			boolean vFlip = (v == 0);
			boolean wFlip = (w == 0);
			boolean xFlip = (x == 0);

			//Actually sets the bits
			yPrime.set(254, aFlip);
			yPrime.set(253, bFlip);
			yPrime.set(252, cFlip);
			yPrime.set(251, dFlip);
			yPrime.set(250, eFlip);
			yPrime.set(249, fFlip);
			yPrime.set(248, gFlip);
			yPrime.set(247, hFlip);
			yPrime.set(246, iFlip);
			yPrime.set(245, jFlip);
			yPrime.set(244, kFlip);
			yPrime.set(243, lFlip);
			yPrime.set(242, mFlip);
			yPrime.set(241, nFlip);
			yPrime.set(240, oFlip);
			yPrime.set(239, pFlip);
			yPrime.set(238, qFlip);
			yPrime.set(237, rFlip);
			yPrime.set(236, sFlip);
			yPrime.set(235, tFlip);
			yPrime.set(234, uFlip);
			yPrime.set(233, vFlip);
			yPrime.set(232, wFlip);
			yPrime.set(231, xFlip);

			//Convert to byte array and cmopare hash to z
			byte[] yPrimeByte = yPrime.toByteArray();
			byte[] yHashed = null;
			try {
				DigestSHA3 md = new DigestSHA3(256);
				md.update(yPrimeByte);
				yHashed = md.digest();
			} catch(Exception ex) {
				ex.printStackTrace();
			}

			//If hash matches z, return yHashed
			if(Arrays.equals(yHashed, z)){
				return yPrimeByte;
			}
		}
		}
		}
		}
		}
		}
		}
		}
		}
		}
		}
		}
		}
		}
		}
		}
		}
		}
		}
		}
		}
		}
		}
		}
		return null;
	}


}