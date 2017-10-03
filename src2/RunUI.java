import java.util.Scanner;
import java.util.*;
import java.util.List;

public class RunUI {
  public static void main(String args[]) {
    System.out.println("Welcome to the File Sharing Program!");

    //Initialize scanner and group and file clients
    Scanner scan = new Scanner(System.in);
    GroupClient gc = new GroupClient();
    FileClient fc = new FileClient();
    UserToken token = null;
    
    //Prompt the user to login to the server to authenticate their token and log in with
    //appropriate permissions
    System.out.println("Default Connection Settings");
    System.out.println("\tServer:\t\t\tlocalhost");
    System.out.println("\tGroup Server Port:\t8765");
    System.out.println("\tFile Server Port:\t4321");
    System.out.print("Use Default Settings? (y/n): ");
    String useDefault = scan.next();
    while (!useDefault.equals("Y") && !useDefault.equals("y") && !useDefault.equals("N") && !useDefault.equals("n")){
        System.out.println("Please enter (y/n): ");
        useDefault = scan.next();
    }

    int groupPort = 8765;
    int filePort = 4321;
    String server = "localhost";

    if (useDefault.equals("N") || useDefault.equals("n")){
        System.out.println("Enter Server: ");
        server = scan.next();
        System.out.println("Enter Group Server Port: ");
        groupPort = scan.nextInt();
        System.out.println("Enter the File Server Port: ");
        filePort = scan.nextInt();
    }

    System.out.println("\nLogin");
    System.out.println("Enter your username: ");
    String username = scan.next();
    int portNumber = 8765;
    gc.connect(server, groupPort);	//Ask for server & port?
    if (gc.isConnected()){
    	token = gc.getToken(username);
    	if (token == null){
    		System.out.println("Invalid username");
    		gc.disconnect();
            System.exit(0);
    	}
    } else {
    	System.out.println("Unable to connect to GroupServer");
    }

    //Asks the user if they want to make operations on files or on groups and connects then
    //displays the appropriate menu (group menu/file menu) for group or file operations

    //Loop to allow user to switch between GroupServer ops and FileServer ops in same session
    int serverChoice = -1;
    while(serverChoice != 0){
        System.out.println("Welcome, " + username + "!\n");
        System.out.println("1. Group operations");
        System.out.println("2. File operations\n");
        System.out.println("0. Disconnect and Exit\n");
        System.out.print("Select an option: ");
        serverChoice = scan.nextInt();

        while(serverChoice != 1 && serverChoice != 2 && serverChoice != 0){
            System.out.println("Please select either 0, 1, or 2: ");
            serverChoice = scan.nextInt();
        }

        //Once the user has selected group/file server, displays operations and completes them
        //on the appropriate server
        
        //GroupServer Menu Handling
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
        } 
        //FileServer Menu Handling
        else if (serverChoice == 2){
            //Connect to FileServer
            fc.connect(server, filePort); 
            if(fc.isConnected()){
                System.out.println("Connected to FileServer");
                int fileMenuChoice = -1;
                while(fileMenuChoice != 0){
                    fileMenuChoice = fileMenu();
                    String destFile, sourceFile, group, fileName;
                    switch(fileMenuChoice){
                        case 1:
                            System.out.println("Upload a file");
                            System.out.println("Enter the name of the local source file: ");
                            sourceFile = scan.next();
                            System.out.println("Enter the name of the destination file: ");
                            destFile = scan.next();
                            System.out.println("Enter the name of the group to which this file should be added:  ");
                            group = scan.next();
                            if(fc.upload(sourceFile, destFile, group, token)){
                                System.out.println(sourceFile + " successfully uploaded as " + destFile + " in group " + group);
                            }
                            else{
                                System.out.println("Error! Unable to upload " + sourceFile);
                            }
                            break;

                        case 2:
                            System.out.println("Download a file");
                            System.out.println("Enter the name of the source file on the server: ");
                            sourceFile = scan.next();
                            System.out.println("Enter the name of the local destination file: ");
                            destFile = scan.next();
                            if(fc.download(sourceFile, destFile, token)){
                                System.out.println(sourceFile + " succesfully downloaded as " + destFile);
                            }
                            else{
                                System.out.println("Error! Unable to download " + sourceFile); 
                            }
                            break;

                        case 3:
                            System.out.println("Delete a file");
                            System.out.println("Enter the name of the file to be deleted");
                            fileName = scan.next();
                            if(fc.delete(fileName, token)){
                                System.out.println(fileName + " succesfully deleted");
                            }
                            else{
                                System.out.println("Error! Unable to delete " + fileName);
                            }
                            break;

                        case 4: 
                            System.out.println("List all files");
                            List<String> files = fc.listFiles(token);
                            if(files != null){
                                int count = files.size();

                                //TROUBLESHOOOTING
                                System.out.println("count = " + count + "\n");

                                for(int i = 0; i < count; i++){
                                    String file = files.get(i);
                                    System.out.println(file);
                                }
                            }
                            else{
                                System.out.println("Error! Unable to retrieve files list");
                            }
                            break;

                        case 0:
                            break;
                        default:
                            System.out.println("Invalid input: Please select an option 0-4");
                            break;
                    }
                    token = gc.getToken(username);
                }
            }
            else{
                System.out.println("Error! Unable to connect to FileServer");
                //TODO: Potentially handle this 
            } 
        }
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
        System.out.println("7. Delete a group");
        System.out.println("");
        System.out.println("0. Exit");
        System.out.print("Select an option: ");
        int choice = scan.nextInt();
        System.out.println("");
        return choice;
  }

  public static int fileMenu(){
        Scanner scan = new Scanner(System.in);
        System.out.println("\nFile Server Menu");
        System.out.println("1. Upload a file");
        System.out.println("2. Download a file");
        System.out.println("3. Delete a file");
        System.out.println("4. List all files\n");
        System.out.println("0. Exit");
        System.out.println("Select an option: ");
        int choice = scan.nextInt();
        System.out.println("");
        return choice;
  }
}
