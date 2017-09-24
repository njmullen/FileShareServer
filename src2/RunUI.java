import java.util.Scanner;
import java.util.*;

public class RunUI {
  public static void main(String args[]) {
    System.out.println("Hello, welcome to the UI.");

    //Initialize scanner and group and file clients
    Scanner scan = new Scanner(System.in);
    GroupClient gc = new GroupClient();
    FileClient fc = new FileClient();
    UserToken token = null;
    
    //Prompt the user to login to the server to authenticate their token and log in with
    //appropriate permissions
    //TODO: Connect to file server
    System.out.println("Enter your username: ");
    String username = scan.next();
    gc.connect("localhost", 8765);	//Ask for server & port?
    if (gc.isConnected()){
    	token = gc.getToken(username);
    	if (token == null){
    		System.out.println("Invalid username");
    		gc.disconnect();
            System.exit(0);
    	}
    } else {
    	System.out.println("Unable to connect to GroupClient");
    }

    //Asks the user if they want to make operations on files or on groups and connects then
    //displays the appropriate menu (group menu/file menu) for group or file operations

    //TODO: Change verbage/logic as user is already "connected" to groupServer but not to
    //file server. Move connection into serverChoice if/else or initiate fileServer connection
    //earlier
    System.out.println("Welcome, " + username + "!");
    System.out.println("");
    System.out.println("1. Connect to GroupServer");
    System.out.println("2. Connect to FileServer");
    System.out.print("Select an option: ");
    int serverChoice = scan.nextInt();

    while(serverChoice != 1 && serverChoice != 2){
        System.out.println("Please select either 1 or 2: ");
        serverChoice = scan.nextInt();
    }

    //Once the user has selected group/file server, displays operations and completes them
    //on the appropriate server
    //TODO: Check for valid input, finish implementation
    if (serverChoice == 1){
        int groupMenuChoice = -1;
        while (groupMenuChoice != 0){
            groupMenuChoice = groupMenu();
            switch(groupMenuChoice){
                //Add a user
                case 1:
                    System.out.println("Create a User");
                    System.out.println("Enter username to be created: ");
                    String newUsername = scan.next();
                    //Checks that current logged in user is an admin, if not, forbids the operation
                    if(token.getGroups().contains("ADMIN")){
                        if(gc.createUser(newUsername, token)){
                            System.out.println(newUsername + " added succesfully!");
                        } else {
                            System.out.println("Error! Unable to add " + newUsername);
                        }
                    } else {
                        System.out.println("Unable to create user; insufficient permissions");
                    }
                    break;
                //Delete a user
                case 2:
                    System.out.println("Delete a User");
                    System.out.println("Enter username to be deleted: ");
                    String deletedUsername = scan.next();
                    //Checks that current logged in user is an admin, if not, forbids the operation
                    if(token.getGroups().contains("ADMIN")){
                        if(gc.deleteUser(deletedUsername, token)){
                            System.out.println(deletedUsername + " deleted succesfully!");
                        } else {
                            System.out.println("Error! Unable to delete " + deletedUsername);
                        }
                    } else {
                        System.out.println("Unable to delete user; insufficient permissions");
                    }
                    break;
                //Create a group
                case 3:
                    System.out.println("Create a Group");
                    System.out.println("Enter the group name: ");
                    String groupName = scan.next();
                    if(gc.createGroup(groupName, token)){
                        System.out.println(groupName + " succesfully created!");
                    } else {
                        System.out.println("Error! Unable to create " + groupName);
                    }
                    break;
                //List members of a group
                case 4:
                    System.out.println("List Members of a Group");
                    System.out.println("Enter a group name: ");
                    String groupToList = scan.next();
                    List<String> memberList = gc.listMembers(groupToList, token);
                    System.out.println("Members of " + groupToList + ":");
                    if (memberList != null){
                        for(int i = 0; i < memberList.size(); i++){
                            System.out.println(memberList.get(i));
                        }
                    } else {
                        System.out.println("Error! Unable to list members of " + groupToList);
                    }
                    break;
                //Add user to group
                case 5:
                    System.out.println("Add User to a Group");
                    System.out.println("Enter the group name: ");
                    String groupToAdd = scan.next();
                    System.out.println("Enter the user to be added: ");
                    String userToAdd = scan.next();
                    if(gc.addUserToGroup(userToAdd, groupToAdd, token)){
                        System.out.println(userToAdd + " succesfully added to " + groupToAdd);
                    } else {
                        System.out.println("Error! Unable to add " + userToAdd + " to " + groupToAdd);
                    }
                    break;
                //Delete user from group:
                case 6:
                    System.out.println("Delete User From a Group");
                    System.out.println("Enter the group name: ");
                    String groupToDeleteFrom = scan.next();
                    System.out.println("Enter the user to be deleted: ");
                    String userToDelete = scan.next();
                    if(gc.deleteUserFromGroup(userToDelete, groupToDeleteFrom, token)){
                        System.out.println(userToDelete + " succesfully deleted from " + groupToDeleteFrom);
                    } else {
                        System.out.println("Error! Unable to delete " + userToDelete + " from " + groupToDeleteFrom);
                    }
                    break;
                case 0:
                    break;
                default:
                    break;
            }
        }
    } else if (serverChoice == 2){
        //int fileMenuChoice = fileMenu();
    }


    
  }

  /*
   * Displays the options for operations on a group and returns the value selected
   * @return choice: user's selection from the menu
   * TODO: Complete the operations, check for valid input
   */
  public static int groupMenu(){
        Scanner scan = new Scanner(System.in);
        System.out.println("\nGroup Server Menu");
        System.out.println("1. Add a user");
        System.out.println("2. Delete a user");
        System.out.println("3. Create a group");
        System.out.println("4. List members of a group");
        System.out.println("5. Add user to group");
        System.out.println("6. Delete user from group");
        System.out.println("");
        System.out.println("0. Exit");
        System.out.print("Select an option: ");
        int choice = scan.nextInt();
        System.out.println("");
        return choice;
  }
}
