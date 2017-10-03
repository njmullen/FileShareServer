import java.util.Scanner;
import java.util.*;
import java.util.List;

public class RunUI {

	public static void main(String args[]){
		Scanner scan = new Scanner(System.in);
        int groupPort = 8765;
        int filePort = 4321;
        String server = "localhost";
        UserToken token = null;

		System.out.println("Welcome to the File Transfer System");
		System.out.println("LOGIN");
		System.out.println("Username: ");
		String username = scan.next();

		System.out.println("Welcome, " + username + ". Login succesful.");
		System.out.println("Connection Settings. Would you like to use default settings? (y/n)");
        System.out.println("\tDefault: Group Server Port: 8765, File Server Port: 4321, Server: localhost");
        String defaultOptions = scan.next();
        while (!defaultOptions.equals("Y") && !defaultOptions.equals("y") && !defaultOptions.equals("N") && !defaultOptions.equals("n")){
            System.out.println("Please enter (y/n): ");
            defaultOptions = scan.next();
        }

        if (defaultOptions.equals("N") || defaultOptions.equals("n")){
            System.out.println("Enter Server: ");
            server = scan.next();
            System.out.println("Enter Group Server Port: ");
            groupPort = scan.nextInt();
            System.out.println("Enter File Server Port: ");
            filePort = scan.nextInt();
        }

        int serverOperation = -1;
		while (serverOperation != 0){
			System.out.println("\nMain Menu");
			System.out.println("1. Group Server Operations");
			System.out.println("2. File Server Operations");
			System.out.println("0. Exit and Disconnect");
			System.out.print("Selection: ");
			int serverOperation = scan.nextInt();
			while(serverOperation != 1 && serverOperation != 2 && serverOperation != 0){
				System.out.println("Please make a valid selection");
				System.out.println("1. Group Server Operations");
				System.out.println("2. File Server Operations");
				System.out.println("0. Exit and Disconnect");
				serverOperation = scan.nextInt();
			}
			System.out.println("");

			switch(serverOperation){
				//Group Server
				case 1:
					//Connects to the group server
					GroupClient gc = new GroupClient();
					gc.connect(server, groupPort);	
				    if (gc.isConnected()){
				    	token = gc.getToken(username);
				    	if (token == null){
				    		System.out.println("Invalid username. Disconnecting.");
				    		gc.disconnect();
				            System.exit(0);
				    	}
				    } else {
				    	System.out.println("Error! Unable to connect to GroupServer");
				    }
					break;

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
		                    //Delete a group
		                    case 7:
		                        System.out.println("Delete a Group");
		                        System.out.println("Enter the group name: ");
		                        String groupToDelete = scan.next();
		                        if(gc.deleteGroup(groupToDelete, token)){
		                            System.out.println(groupToDelete + " succesfully deleted");
		                        } else {
		                            System.out.println("Error! Unable to delete " + groupToDelete);
		                        }
		                        break;
		                    case 0:
		                        break;
		                    default:
		                        System.out.println("Invalid input: Please select an option 0-7");
		                        break;
		                }
		                //Refresh the user token
		                token = gc.getToken(username);
		            }
				//File Server
				case 2:
					break;
				//Disconnect
				case 0:
					break;

			}//end switch(server operation)
		}//end while (server operation)
	}//end main
}//end class