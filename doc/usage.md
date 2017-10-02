# Using the File Server

## Compiling

Type javac *.java from the command line

## Starting the Group Server

Type java RunGroupServer <portnumber> where <portnumber> is an optional integer for the desired port to start the group server.
Omitting <portnumber> will default the group server to start on port 8765.

## Starting the File Server

Type java RunFileServer <portnumber> where <portnumber> is an optional integer for the desired port to start the file server.
Omitting <portnumber> will default the file server to start on port 4321.

## Starting the UI

Type java RunUI <groupserver portnumber> <fileserver portnumber> where <groupserver portnumber> and <fileserver portnumber> are optional integers for the desired ports to communicate with the group and file servers.
Ommitting both integers will connect with the group server using port 8765, and the file server using port 4321.
Ommiting the second integer will connect the group server with the entered integer, and the file server using port 4321.

Once the UI is running, users can login and will be presented with a menu that gives two options: group operations and file operations.
Group operations contain group functionality (add user/delete user/group management) and file operations contain file functionality (upload/download/etc)
