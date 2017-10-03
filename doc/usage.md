# Using the Program

## Compiling

Type `javac *.java` from the command line

## Starting the Group Server

Type `java RunGroupServer <portnumber>` where <portnumber> is an optional integer for the desired port to start the group server.
Omitting <portnumber> will default the group server to start on port 8765.

## Starting the File Server

Type `java RunFileServer <portnumber>` where <portnumber> is an optional integer for the desired port to start the file server.
Omitting <portnumber> will default the file server to start on port 4321.

## Starting the UI

Type `java RunUI`, which will start the user interface. 
Once the UI is running, users will have the option to either specify a desired server, group server port, and file server port, or use the defaults ("localhost", 8765, 4321). Then, users can login and will be presented with a menu that gives two options: group operations and file operations.
Group operations contain group functionality (add user/delete user/group management) and file operations contain file functionality (upload/download/etc)
