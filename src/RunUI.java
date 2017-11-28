import java.util.Scanner;
import java.util.*;
import java.util.List;
import java.io.*;
import java.security.*;
import javax.crypto.*;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;

import org.bouncycastle.jce.provider.*;
import java.security.spec.*;
import java.security.*;
import org.bouncycastle.jcajce.provider.digest.SHA3.DigestSHA3;
import org.bouncycastle.util.encoders.Hex;
import java.math.*;

public class RunUI {

  public static void main(String args[]) {
    System.out.println("Welcome to the File Sharing Program!");

    //Initialize scanner and group and file clients
    Scanner scan = new Scanner(System.in);
    GroupClient gc = new GroupClient();
    FileClient fc = new FileClient();

    EncryptedToken token = null;
    byte[] tokenBytes = null;
    String tokenSig = null;

    String username = null;

    Key gsAESKey = null;
    Key fsAESKey = null;
    ArrayList<GroupKeyList> groupKeys = null;

    Security.addProvider(new BouncyCastleProvider());

    //Prompt the user to ask if they want to use default server settings or custom settings
    System.out.println("Default Connection Settings");
    System.out.println("\tGroup Server:\t\tlocalhost");
    System.out.println("\tGroup Server Port:\t8765");
    System.out.println("\tFile Server:\t\tlocalhost");
    System.out.println("\tFile Server Port:\t4321");
    System.out.print("Use Default Settings? (y/n): ");
    String useDefault = scan.next();
    while (!useDefault.equals("Y") && !useDefault.equals("y") && !useDefault.equals("N") && !useDefault.equals("n")){
        System.out.println("Please enter (y/n): ");
        useDefault = scan.next();
    }

    //Default settings if user chooses not to change them
    int groupPort = 8765;
    int filePort = 4321;
    String groupServerChoice = "localhost";
    String fileServerChoice = "127.0.0.1";

    //If the user chooses to use custom settings, connect with those, otherwise defaults
    if (useDefault.equals("N") || useDefault.equals("n")){
        System.out.println("Enter Group Server: ");
        groupServerChoice = scan.next();
        System.out.println("Enter Group Server Port: ");
        groupPort = scan.nextInt();
        System.out.println("Enter File Server: ");
        fileServerChoice = scan.next();
        System.out.println("Enter the File Server Port: ");
        filePort = scan.nextInt();
    }

    //Open connections to GroupServer and FileServer
    gc.connect(groupServerChoice, groupPort);
    fc.connect(fileServerChoice, filePort);

    if (gc.isConnected()){
        //Asks the server for its public key
        PublicKey groupKey = gc.getPublicKey();
        boolean isMatch = false;

        //Check against list of known public keys
        try {
            ObjectInputStream in = new ObjectInputStream(new FileInputStream("knownServers.txt"));
            List<PublicKey> keyList = (List<PublicKey>) in.readObject();
            in.close();

            //If the list of known keys contains this one, allow entry
            if(keyList.contains(groupKey)){
                isMatch = true;
            }

        //If it cannot find a list of trusted keys, ask if the user wants to start one
        } catch (FileNotFoundException ex){
            System.out.println("Attempting to connect to server. Please verify the server's public key");
            System.out.println("\nGroupServer Key: " + groupKey);
            System.out.println("\nConnect? (y/n): ");
            String connectToKey = scan.next();
            while (!connectToKey.equals("Y") && !connectToKey.equals("y") && !connectToKey.equals("N") && !connectToKey.equals("n")){
                System.out.println("Please enter (y/n): ");
                connectToKey = scan.next();
            }

            if (connectToKey.equals("Y") || connectToKey.equals("y")){
                //Add to new file called knownServers.txt
                try {
                    List<PublicKey> list = new ArrayList<PublicKey>();
                    list.add(groupKey);
                    ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("knownServers.txt"));
                    out.writeObject(list);
                    out.close();
                    isMatch = true;
                } catch (Exception exa){
                    ex.printStackTrace();
                }
            } else {
                System.out.println("Not trusted. exiting");
                System.exit(0);
            }
        } catch (Exception exd) {
            exd.printStackTrace();
        }

        if (!isMatch){
            //If didn't find public key, but file already exists, ask if want to connect
            System.out.println("Attempting to connect to server. Please verify the server's public key");
            System.out.println("\nGroupServer Key: " + groupKey);
            System.out.println("\nConnect? (y/n): ");
            String connectToKey = scan.next();
            while (!connectToKey.equals("Y") && !connectToKey.equals("y") && !connectToKey.equals("N") && !connectToKey.equals("n")){
                System.out.println("Please enter (y/n): ");
                connectToKey = scan.next();
            }
            if (connectToKey.equals("Y") || connectToKey.equals("y")){
                //Add to new file called knownServers.txt
                try {
                    ObjectInputStream in = new ObjectInputStream(new FileInputStream("knownServers.txt"));
                    List<PublicKey> keyList = (List<PublicKey>) in.readObject();
                    in.close();

                    keyList.add(groupKey);
                    ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("knownServers.txt"));
                    out.writeObject(keyList);
                    out.close();
                } catch (Exception ex){
                    ex.printStackTrace();
                }
            } else {
                System.out.println("Not trusted. Exiting");
                System.exit(0);
            }
        }

        //Do D-H Exchange with GroupServer
        DHParameterSpec dhSpec = null;
        try {
            AlgorithmParameterGenerator dhGenerator = AlgorithmParameterGenerator.getInstance("DH");
            dhGenerator.init(1024, new SecureRandom());
            AlgorithmParameters dhParameters = dhGenerator.generateParameters();
            dhSpec = (DHParameterSpec)dhParameters.getParameterSpec(DHParameterSpec.class);
        } catch (Exception ex){
            ex.printStackTrace();
        }

        //s = the secret number that the server generates
        //p = the prime number
        //g = prime number generator
        //S = the calculated half key of the server (g^s mod p)
        Random random = new Random();
        BigInteger c = new BigInteger(1024, random);
        BigInteger p = dhSpec.getP();
        BigInteger g = dhSpec.getG();
        BigInteger C = g.modPow(c, p);

        BigInteger S = gc.performDiffie(p, g, C);
        BigInteger dhKey = S.modPow(c, p);

        //AES
        //Generate AES key with 1st 16 bits of DH key
        byte[] dhKeyBytes = dhKey.toByteArray();
        byte[] shortBytes = new byte[16];

        for(int i = 0; i < 16; i++){
            shortBytes[i] = dhKeyBytes[i];
        }

        gsAESKey = null;
        try{
            gsAESKey = new SecretKeySpec(shortBytes, "AES");
        }
        catch(Exception ex){
            ex.printStackTrace();
        }

        gc.setAESKey(gsAESKey);

    } else {
    	System.out.println("Unable to connect to GroupServer");
    }

    //Start connection to FileServer
    if(fc.isConnected()){
        //Check if FileServer key has been trusted before, if not, ask user to
        //verify FileServer's piublic key
        PublicKey fileKey = fc.getPublicKey();
        boolean isMatch = false;
        //Check against list of known public keys
        try {
            ObjectInputStream in = new ObjectInputStream(new FileInputStream("knownServers.txt"));
            List<PublicKey> keyList = (List<PublicKey>) in.readObject();
            in.close();

            //If the list of known keys contains this one, allow entry
            if(keyList.contains(fileKey)){
                isMatch = true;
            }
        //If it cannot find a list of trusted keys, ask if the user wants to start one
        } catch (FileNotFoundException ex){
            System.out.println("Attempting to connect to server. Please verify the server's public key");
            System.out.println("\nFileServer Key: " + fileKey);
            System.out.println("\nConnect? (y/n): ");
            String connectToKey = scan.next();
            while (!connectToKey.equals("Y") && !connectToKey.equals("y") && !connectToKey.equals("N") && !connectToKey.equals("n")){
                System.out.println("Please enter (y/n): ");
                connectToKey = scan.next();
            }

            if (connectToKey.equals("Y") || connectToKey.equals("y")){
                //Add to new file called knownServers.txt
                try {
                    List<PublicKey> list = new ArrayList<PublicKey>();
                    list.add(fileKey);
                    ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("knownServers.txt"));
                    out.writeObject(list);
                    out.close();
                    isMatch = true;
                } catch (Exception exa){
                    ex.printStackTrace();
                }
            } else {
                System.out.println("Not trusted. exiting");
                System.exit(0);
            }
        } catch (Exception exd) {
            exd.printStackTrace();
        }

        if (!isMatch){
            //If didn't find public key, but file already exists, ask if want to connect
            System.out.println("Attempting to connect to server. Please verify the server's public key");
            System.out.println("\nFileServer Key: " + fileKey);
            System.out.println("\nConnect? (y/n): ");
            String connectToKey = scan.next();
            while (!connectToKey.equals("Y") && !connectToKey.equals("y") && !connectToKey.equals("N") && !connectToKey.equals("n")){
                System.out.println("Please enter (y/n): ");
                connectToKey = scan.next();
            }
            if (connectToKey.equals("Y") || connectToKey.equals("y")){
                //Add to new file called knownServers.txt
                try {
                    ObjectInputStream in = new ObjectInputStream(new FileInputStream("knownServers.txt"));
                    List<PublicKey> keyList = (List<PublicKey>) in.readObject();
                    in.close();

                    keyList.add(fileKey);
                    ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("knownServers.txt"));
                    out.writeObject(keyList);
                    out.close();
                } catch (Exception ex){
                    ex.printStackTrace();
                }
            } else {
                System.out.println("Not trusted. exiting");
                System.exit(0);
            }
        }

        //Do D-H Exchange
        DHParameterSpec dhSpec = null;
        try {
            AlgorithmParameterGenerator dhGenerator = AlgorithmParameterGenerator.getInstance("DH");
            dhGenerator.init(1024, new SecureRandom());
            AlgorithmParameters dhParameters = dhGenerator.generateParameters();
            dhSpec = (DHParameterSpec)dhParameters.getParameterSpec(DHParameterSpec.class);
        } catch (Exception ex){
            ex.printStackTrace();
        }

        //s = the secret number that the server generates
        //p = the prime number
        //g = prime number generator
        //S = the calculated half key of the server (g^s mod p)
        Random random = new Random();
        BigInteger c = new BigInteger(1024, random);
        BigInteger p = dhSpec.getP();
        BigInteger g = dhSpec.getG();
        BigInteger C = g.modPow(c, p);

        BigInteger S = fc.performDiffie(p, g, C);
        BigInteger dhKey = S.modPow(c, p);

        byte[] dhKeyBytes = dhKey.toByteArray();
        byte[] shortBytes = new byte[16];

        for(int i = 0; i < 16; i++){
            shortBytes[i] = dhKeyBytes[i];
        }

        try{
            fsAESKey = new SecretKeySpec(shortBytes, "AES");
        }
        catch(Exception ex){
            ex.printStackTrace();
        }

        //Give key to client
        fc.setAESKey(fsAESKey);

        //After the FileServer is connected to and authenticated, connect the FileServer
        //to the GroupServer to get its public key to verify tokens.
        boolean fileGroupKeyExchange = fc.getGroupServerKey(groupServerChoice, groupPort);
        if (!fileGroupKeyExchange){
            System.out.println("FS/GS Key exchange failed");
            System.exit(0);
        }
    } else {
        System.out.println("Unable to connect to FileServer");
    }

    //Create AESEnncrypted who can hold state
    AESEncrypter aesUsername = new AESEncrypter(gsAESKey);
    AESEncrypter aesPassword = new AESEncrypter(gsAESKey);

    //Prompts the user for a login, then connects to the group server using the specified
    //port and server and allows access if it can be authenticated by the group server
    System.out.println("\nLogin");
    System.out.println("Enter your username: ");
    username = scan.next();
    System.out.println("Enter your password: ");
    String passwordEntry = scan.next();
    int passwordAttempts = 1;

    //Encrypt username and password to send to server
    EncryptedMessage encryptedUser = aesUsername.encrypt(username);
    EncryptedMessage encryptedPass = aesPassword.encrypt(passwordEntry);

    //Send encrypted user and password
    //Checks to see if the password is invalid; denies entry if it is entered incorrectly
    //5 times
    while (!gc.checkPassword(encryptedUser, encryptedPass) && passwordAttempts <= 5){
        System.out.println("Invalid username or password. Please try again");
        System.out.println("Enter your username: ");
        username = scan.next();
        System.out.println("Enter your password: ");
        passwordEntry = scan.next();
        passwordAttempts++;

        AESEncrypter aesUsernamePrime = new AESEncrypter(gsAESKey);
        AESEncrypter aesPasswordPrime = new AESEncrypter(gsAESKey);

        encryptedUser = aesUsernamePrime.encrypt(username);
        encryptedPass = aesPasswordPrime.encrypt(passwordEntry);
    }
    //Denies entry if more than 5 attempts were made
    if(passwordAttempts > 5){
        System.out.println("Incorrect username or password. Too many attempts. Exiting");
        System.exit(0);
    }

    //If password was entered succesfully, grab the users token.
    //If the username doesn't exist, throw invalid username, though this would have
    //said invalid password and kicked user out before this is reached
    token = gc.getToken(username, fileServerChoice, filePort);
    groupKeys = gc.getGroupKeys();
    // //TROUBLESHOOTING
    // System.out.println("GroupKeySize after login "+groupKeys.size());
    // for( GroupKey k : groupKeys ) {
    //   System.out.println(k.getName());
    // }

    if (token == null){
        System.out.println("Invalid username");
        gc.disconnect();
          System.exit(0);
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
                        String newUsername = checkForPipe(scan);
                        System.out.println("Set a password for that user: ");
                        String password = checkForPipe(scan);
                        //Checks that current logged in user is an admin, if not, forbids the operation
                        if(gc.createUser(newUsername, password, token)){
                            System.out.println(newUsername + " added succesfully!");
                        } else {
                            System.out.println("Error! Unable to add " + newUsername);
                        }

                        break;
                    //Delete a user
                    case 2:
                        System.out.println("Delete a User");
                        System.out.println("Enter username to be deleted: ");
                        String deletedUsername = scan.next();
                        //Checks that current logged in user is an admin, if not, forbids the operation
                        if(gc.deleteUser(deletedUsername, token)){
                            System.out.println(deletedUsername + " deleted succesfully!");
                        } else {
                            System.out.println("Error! Unable to delete " + deletedUsername);
                        }

                        break;
                    //Create a group
                    case 3:
                        System.out.println("Create a Group");
                        System.out.println("Enter the group name: ");
                        String groupName = checkForPipe(scan);
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
                //Refresh the user token and group keys (necessary for cgroup / delete user)
                token = gc.getToken(username, fileServerChoice, filePort);
                groupKeys = gc.getGroupKeys();
            }
        }
        //FileServer Menu Handling
        else if (serverChoice == 2){
            int fileMenuChoice = -1;
            //Decrypt the Token with the GS AES Key and re-encrypt it with the FS AES Key
            EncryptedMessage tokenP = token.getToken();
            EncryptedMessage sigP = token.getSignature();

            AESDecrypter tokenD = new AESDecrypter(gsAESKey);
            AESDecrypter sigD = new AESDecrypter(gsAESKey);

            byte[] tokenB = tokenD.decryptBytes(tokenP);
            byte[] sigB = sigD.decryptBytes(sigP);

            AESEncrypter tokenE = new AESEncrypter(fsAESKey);
            AESEncrypter sigE = new AESEncrypter(fsAESKey);

            EncryptedMessage tokenM = tokenE.encrypt(tokenB);
            EncryptedMessage sigM = sigE.encrypt(sigB);
            EncryptedToken fsToken = new EncryptedToken(tokenM, sigM);

            while(fileMenuChoice != 0){
                fileMenuChoice = fileMenu();

                String destFile, sourceFile, group, fileName;
                switch(fileMenuChoice){
                    //Upload a file
                    case 1:
                        System.out.println("Upload a file");
                        System.out.println("Enter the name of the local source file: ");
                        sourceFile = scan.next();
                        System.out.println("Enter the name of the destination file: ");
                        destFile = scan.next();
                        System.out.println("Enter the name of the group to which this file should be added:  ");
                        group = scan.next();
                        if(fc.upload(sourceFile, destFile, group, fsToken, groupKeys)){
                            System.out.println(sourceFile + " successfully uploaded as " + destFile + " in group " + group);
                        }
                        else{
                            System.out.println("Error! Unable to upload " + sourceFile);
                        }
                        break;
                    //Download a file
                    case 2:
                        System.out.println("Download a file");
                        System.out.println("Enter the name of the source file on the server: ");
                        sourceFile = scan.next();
                        System.out.println("Enter the name of the local destination file: ");
                        destFile = scan.next();
                        if(fc.download(sourceFile, destFile, fsToken, groupKeys)){
                            System.out.println(sourceFile + " succesfully downloaded as " + destFile);
                        }
                        else{
                            System.out.println("Error! Unable to download " + sourceFile);
                        }
                        break;
                    //Delete a file
                    case 3:
                        System.out.println("Delete a file");
                        System.out.println("Enter the name of the file to be deleted");
                        fileName = scan.next();
                        if(fc.delete(fileName, fsToken)){
                            System.out.println(fileName + " succesfully deleted");
                        }
                        else{
                            System.out.println("Error! Unable to delete " + fileName);
                        }
                        break;
                    //List all files available to that user
                    case 4:
                        System.out.println("List all files");
                        List<String> files = fc.listFiles(fsToken);
                        if(files != null){
                            int count = files.size();
                            System.out.println(count + " files available");
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
            }
        }
    }

  }

  /*
   * Displays the options for operations on a group and returns the value selected
   * @return choice: user's selection from the menu
   */
  public static int groupMenu(){
        Scanner scan = new Scanner(System.in);
        System.out.println("\nGroup Server Menu");
        System.out.println("1. Create a new user");
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

  public static String checkForPipe(Scanner scan) {
        String input = scan.next();
        while(input.contains("|") || input.contains("/") ) {
          System.out.println("Invalid: Cannot contain \'|\' or \'/\'\nTry again.");
          input = scan.next();
        }
        return input;
  }
}
