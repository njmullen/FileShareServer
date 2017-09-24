public class RunGroupClient{

	public static void main(String[] args){
		GroupClient client = new GroupClient();
		client.connect("localhost", 8765);
		client.displayMenu();
	}

}