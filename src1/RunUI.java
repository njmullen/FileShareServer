import java.util.Scanner;

public class RunUI {
  public static void main(String args[]) {
    System.out.println("Hello, welcome to the UI.");

    Scanner in = new Scanner(System.in);
    GroupClient gc = new GroupClient();

    gc.connect("localhost", 8765);
    System.out.println(gc.getToken("conor").getSubject());
    System.out.println("Cool your in, bye!");
    gc.disconnect();
  }
}
