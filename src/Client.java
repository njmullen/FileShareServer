import java.net.Socket;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public abstract class Client {

	/* protected keyword is like private but subclasses have access
	 * Socket and input/output streams
	 */
	protected Socket sock;
	protected ObjectOutputStream output;
	protected ObjectInputStream input;

	public boolean connect(final String server, final int port) {
		try {
			sock = new Socket(server, port);
			System.out.println("Connected to " + server + " on port " + port);

			// Set up I/O streams with the server
	    	output = new ObjectOutputStream(sock.getOutputStream());
	    	input = new ObjectInputStream(sock.getInputStream());
		} catch(Exception e){
			System.err.println("Error: " + e.getMessage());
	    e.printStackTrace(System.err);
			return false;
		}
		return true;

	}

	public boolean isConnected() {
		if (sock == null || !sock.isConnected()) {
			return false;
		}
		else {
			return true;
		}
	}

	public void disconnect()	 {
		if (isConnected()) {
			try
			{
				Envelope message = new Envelope("DISCONNECT");
				output.writeObject(message);
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
	}
}
