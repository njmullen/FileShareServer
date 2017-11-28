/* Group server. Server loads the users from UserList.bin.
 * If user list does not exists, it creates a new list and makes the user the server administrator.
 * On exit, the server saves the user list to file.
 */

import java.net.ServerSocket;
import java.net.Socket;
import java.io.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;
import org.bouncycastle.jce.provider.*;
import java.security.spec.*;
import org.bouncycastle.jcajce.provider.digest.SHA3.DigestSHA3;
import org.bouncycastle.util.encoders.Hex;

public class GroupServer extends Server {

	public static final int SERVER_PORT = 8765;
	int currentPort = 8765;
	public UserList userList;
	KeyPair keyPair = null;
	KeyPairGenerator rsaKeyGenerator = null;

	public GroupServer() {
		super(SERVER_PORT, "ALPHA");
		Security.addProvider(new BouncyCastleProvider());
	}

	public GroupServer(int _port) {
		super(_port, "ALPHA");
		currentPort = _port;
		Security.addProvider(new BouncyCastleProvider());

	}

	public void start() {
		// Overwrote server.start() because if no user file exists, initial admin account needs to be created
		System.out.println("Running on port "+ currentPort);
		String userFile = "UserList.bin";
		Scanner console = new Scanner(System.in);
		ObjectInputStream userStream;
		ObjectInputStream groupStream;

		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		runtime.addShutdownHook(new ShutDownListener(this));

		//Open user file to get user list
		try
		{
			FileInputStream fis = new FileInputStream(userFile);
			userStream = new ObjectInputStream(fis);
			userList = (UserList)userStream.readObject();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("UserList File Does Not Exist. Creating UserList...");
			System.out.println("No users currently exist. Your account will be the administrator.");
			System.out.print("Enter your username: ");
			String username = console.next();
			System.out.println("Enter a password: ");
			String password = console.next();

			byte[] passwordHash = null;
			try {
				DigestSHA3 md = new DigestSHA3(256); 
  				md.update(password.getBytes("UTF-8"));
  				passwordHash = md.digest();
			} catch(Exception ex) {
				ex.printStackTrace();
			}

			//Create a new list, add current user to the ADMIN group. They now own the ADMIN group.
			userList = new UserList();
			userList.addUser(username, passwordHash);
			userList.addGroup(username, "ADMIN");
			userList.addOwnership(username, "ADMIN");

			//Generate a 128-bit AES key for file encryption under ADMIN group
			//Generate 128-bit AES key for file encryption 
			try{
				KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
				keyGen.init(128);
				SecretKey key = keyGen.generateKey();

				//Write key to file
				//Format: [group name 1] | [key 1] || [group name 2] | [key 2] || ...
				FileOutputStream groupKeyWrite = new FileOutputStream("groupKeyList", true);
				byte[] keyBytes = Base64.getEncoder().encode(key.getEncoded());
				groupKeyWrite.write(new String("ADMIN").getBytes());
				groupKeyWrite.write(new String("|").getBytes());
				groupKeyWrite.write(keyBytes);
				groupKeyWrite.write(new String("|").getBytes());
				
				groupKeyWrite.close();
			}
			catch (Exception ex){
				ex.printStackTrace();
			}

			//Create the public/private keypair for the server
			//Generate the keypair
			try{
				rsaKeyGenerator = KeyPairGenerator.getInstance("RSA");
	        	rsaKeyGenerator.initialize(2048);
	        	keyPair = rsaKeyGenerator.generateKeyPair();

				PublicKey publicKey = keyPair.getPublic();
	    		PrivateKey privateKey = keyPair.getPrivate();

				//Write out the public key
				FileOutputStream publicKeyWrite = new FileOutputStream("groupPublicKey");
				byte[] pubKey = publicKey.getEncoded();
				publicKeyWrite.write(pubKey);
				publicKeyWrite.close();

				//Write out the private key
				FileOutputStream privateKeyWrite = new FileOutputStream("groupPrivateKey");
				byte[] privKey = privateKey.getEncoded();
				privateKeyWrite.write(privKey);
				privateKeyWrite.close();
			} catch(Exception ex){
				ex.printStackTrace();
			}
			
			
		}
		catch(IOException e)
		{
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}
		catch(Exception ex){
			ex.printStackTrace();
		}

		//Autosave Daemon. Saves lists every 5 minutes
		AutoSave aSave = new AutoSave(this);
		aSave.setDaemon(true);
		aSave.start();

		//This block listens for connections and creates threads on new connections
		try
		{

			final ServerSocket serverSock = new ServerSocket(port);

			Socket sock = null;
			GroupThread thread = null;

			while(true)
			{
				sock = serverSock.accept();
				thread = new GroupThread(sock, this);
				thread.start();
			}
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}

	}

}

//This thread saves the user list
class ShutDownListener extends Thread
{
	public GroupServer my_gs;

	public ShutDownListener (GroupServer _gs) {
		my_gs = _gs;
	}

	public void run()
	{
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;
		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
			outStream.writeObject(my_gs.userList);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

class AutoSave extends Thread
{
	public GroupServer my_gs;

	public AutoSave (GroupServer _gs) {
		my_gs = _gs;
	}

	public void run()
	{
		do
		{
			try
			{
				Thread.sleep(300000); //Save group and user lists every 5 minutes
				System.out.println("Autosave group and user lists...");
				ObjectOutputStream outStream;
				try
				{
					outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
					outStream.writeObject(my_gs.userList);
				}
				catch(Exception e)
				{
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}
			}
			catch(Exception e)
			{
				System.out.println("Autosave Interrupted");
			}
		}while(true);
	}
}
