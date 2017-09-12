Conor Lamb, col26@pitt.edu, github: pere5troika
Nick Mullen, njm72@pitt.edu, github: njmullen
Riley Marzka, rjm132@pitt.edu, github: ImFromMarzKa


#Project 1


##Security Properties


Group Validity: If a file is shared with specific members of a group, other members outside of that group should not be able to do any actions (read, modify, delete, or see and existence or activity) related to that file. Without this rule, members’ activity will be without privacy and thus actions and file that were meant for specific users will be public to all users. 


Prompt Removal: Users who have been removed from the system or from a group should have permissions revoked immediately. The goal is to prevent a latency between the time at which a user is removed, and the time at which the user can no longer access the system. Without this users can tamper with the system before they are actually removed.


Registered Users: Only users who are registered (already have an account with the service) and belong to a group may add/edit/view files, create or delete user groups, and manage who is a member of groups. Without this property, anyone in the world, whether they are users or not, would be able to access the system.


Download Security: Ensure that when downloading a file f, that the download stream can only be utilized by user u who has requested to download file f. No outside party has any sort of access to filestream f. Without this property, malicious users could tamper with the download stream user u is receiving.


File Integrity: Ensure that when downloading or uploading a file, files will not be modified by the system in any way, unless they are edited by a user with appropriate privileges. Without this property, files could be modified in arbitrary/unexpected ways. 


Malicious Content Scanning: Ensure that any file uploaded to the server by any user does not contain any known malicious content. Without this requirement, the server could inadvertently host malicious content and that content could be downloaded by other users or compromise the system.


Secure Connections: Only permit secure connections to the server. Without this requirement, insecure connections could allow malicious content to be hosted on the server, or the information being transferred to and from the server could be intercepted by a third party.


Limited Delay: Modifications, additions, deletions, etc. of files should be updated uniformly across the group(s) within which it is contained without much latency. Without this property, the system could have issues with file integrity. A file could be deleted by one user, but if there is latency between the deletion and the actual removal from the system, then another user could modify the file in that time. This could create an inconsistent state within the system.


Upload Limits: Sizes/Bandwidths of uploads should be limited to a point where the servers can safely handle the incoming data as well as to avoid bottlenecking other users’ experiences on the server. Without this requirement, the server could be overloaded or go down, thus rendering it unavailable for other users. 


Constant Privilege Checking: Every action on the server is checked against privilege levels; users are not authenticated just once when they login to the system, but they are checked for appropriate permissions on every file access/action to ensure they continue to have sufficient privilege to access files. Checking a user’s privileges with each action will eliminate threats from users who maliciously got onto the server and thus keeping them from continuing to access the system.


Privilege Levels: No user can perform tasks which are outside the scope of their privilege level. Only administrative accounts can perform certain tasks, such as add and remove users from the system, adjust privilege levels of other users, etc. This property prevents users from removing other users, raising their own privilege level, etc. It creates a separation of power within the system.


Least Amount of Privilege: The least amount of privilege will be granted for each action; for example, when performing a task that requires basic privilege, administrator accounts will only function with the minimum amount of privilege necessary. This requirement ensures that administrative privileges are only used when performing administrative tasks. This minimizes the permissions which an attacker can attain upon a system breach.


System Usability: The system should be easy enough to use in a secure way that users will not unintentionally breach security, due to the complexity of the system. Without this requirement, users could inadvertently access or modify files that they do not have sufficient privilege or knowledge to access, rendering the server insecure or unavailable for other users.


User Account Security: User saved information will be secured and hidden. Passwords will require a specific length and only the hashes will be stored to the servers. Without this requirement, passwords or other personal user information could be exposed to other users or third parties.


Failover Planning: Contingency plans and fail-over servers will be active to prevent network attacks and server outages. Without this requirement, if main servers failed, the system would be inaccessible to users. The backup server must also be equipped with the same level of security as the main server, so as to prevent attacks on the backup server that wouldn’t be successful on the main server. The main servers will be routinely backed up to the backup servers for minimized downtime.


Intermittent Auto-Sync: After a predetermined time intervals, there will be a user-session data sync. If the connection is lost in the middle of a session, this property will prevent mass user data loss whether there’s an outage on our side or the client side. This “unsaved” data will be easily recoverable upon initiation of the user’s next session.


##Threat Models


###Bear Fur Company


Our file sharing system would be used at a company that sells bear furs. They use the system to host collaborative documents on different teams (sales, marketing, IT, bear hunters, skinners, etc.). Managers in each department create documents which are collaborated on by employees. Employees often download files to work on at home, and then upload their changes. Since the file server is only to be used inside of the company, the main security concern is preventing employees from seeing files not directly shared with them. 


All Employees will each have their own private accounts. Managers should be able to control access to files to their teams. Marketing teams shouldn’t be able to access sales documents unless they are explicitly shared. Also, employees shouldn’t be able to overwrite or edit other employee’s documents unless explicitly shared.


-Group Validity: group validity is very important because it ensures that employees not belonging to a group, cannot see that group’s files.
-File Integrity: file integrity ensures that employees files are not being overwritten or modified by users not permitted to edit them.
-Privilege Levels: privilege levels ensures that managers are the only ones who can add/remove users from groups, allow employees to collaborate on specific files, and to ensure that users are not editing files for which they do not have direct access to


###Public File Tracker


NotIllegalWarez™ is a website where anonymous users can upload any file and share links to it. The servers need to be able to handle many simultaneous uploads and downloads at once. Files should be able to be uploaded or download but cannot be modified. There is not account features on this site, only anonymous users who can share links to their uploads. The site needs to maintain many different, separate types of files without them being corrupted.


Any user can upload or download any file that is hosted on the system. Since there are no accounts, any file can be shared with anyone or downloaded by anyone. Users will not have access to delete or modify any other file on the system, except their own, which they cannot modify once uploaded, only delete. Administrators will have the ability to delete files that violate the ToS or are judged by the administrator or the server to contain malicious content. 


- Download Security: Download security is very important because it ensures that while a user is downloading a file it cannot be modified in a malicious or unintended way. 
- File Integrity: File integrity is important in this system because files are not to be modified at all at any time between upload to the server and download from the server.
- Malicious Content Scanning: Our system cannot allow users to upload file containing viruses or other malicious content. 
- Upload Limit: Limiting the upload size will prevent servers getting plugged by massive file uploads
- System Usability: Since users on the system do not need an account, there cannot be any assumptions made about their intelligence. Therefore, we need to design the website such that users can easily use and understand it so they only upload and download the files they intend. 


###Nuclear Submarine


This scenario is about a nuclear submarine carrying a radioactive payload. The submarine is full of military personnel of varying ranks. The submersible often dives below the sea level and thus requires intense safety measures to make sure the hull isn’t breached nor other capacities of the sub lost. We also need to account for enemies of the sub trying to hack the file system and deter the sub’s mission objectives.


Since the submarine contains many different positions and rankings of sailors, there are multiple privilege levels to access different files, thus it must be ensured that only registered users with appropriate permissions can access files. It also must be ensured that only people who are on the submarine or controlling the operations of the submarine can access files, and those files cannot be intercepted or modified by someone who is not an authorized user.


-Prompt Removal: Upon a crew member’s permission being revoked for any reason, it is important that he or she can no longer access the system. It is presumed that permissions would be revoked due to a transgression on the part of the crew member, leading to the assumption that the crew member has malicious intent.
-File Integrity: File integrity is important to ensure that no files on the system have been tampered with in a malicious way. If any files have been tampered with it could hinder the crew’s ability to complete their mission. 
-Constant Privilege Checking: This is essential to prevent back doors into the system. Whenever any user attempts to perform an action within the system, his privilege level must be checked to verify that he is permitted to complete the action
-Privilege Levels: There must be a separation of privileges within the system because each rank of crew member should only be allowed to perform certain tasks. A lieutenant for example has a lot more privilege than an officer, for example
-User Account Security: It is important than no one can impersonate another user in the system. This could lead to malicious tampering and gathering of information
-Failover Planning: It is essential that there be a plan, should catastrophic failure occur. Without failover planning and with a radioactive payload, countless lives could be lost due to a system failure
-System Usability: It is important that the crew knows how to properly use the system. In an emergency situation, the crew must know and be able to use the system like the back of their hand
-Least Amount of Privilege: In the case of a system breach, it is important that system access is mitigated so that an attacker does not gain access to everything, such as military secrets and launch codes.