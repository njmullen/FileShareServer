# Project: Phase 3
## Conor Lamb, Nick Mullen, Riley Marzka

## T1: Unauthorized Token Issuance
### T1 (a). Threat Description 
To carry out any actions on our file sharing system, a user needs to have a token which contains his or her own group permissions for file sharing actions. With each action both, the group and individual file servers, check the user’s supplied token to authenticate that a user is allowed to take said action. Our file sharing system relies on these token checks to grant permissions for each connected user, thus it is of utmost importance for the entity (our group server) that distributes tokens to users always allocates the correct token (permissions) to the specific user who owns that token. A token mistakenly or insecurely obtained by a different user than the proper owner will grant improper user privileges to see, steal, and manipulate another user’s confidential files as well as the possibility of modifying or deleting their group’s status. In our current build, we implement a very weak form of authentication as well as transmit tokens without integrity nor confidentiality. Our user authentication only asks for the name of a user before logging them in (authenticating them). This means that solely knowing a username (visible publicly to all peers in a group), grants anyone who knows the username the ability to log in as that user. Upon receiving a correct username, our build will then insecurely (in plaintext on a public channel without an integrity check) transmit the usertoken to the user. This means that an adversary can see the token and 1. Know all about a user’s permissions. 2. Take a user’s user token and impersonate them in our system 3. Manipulate the token that was sent to the user.

### T1 (b). Solution

The group server, which allocates the tokens to users initially logging in, must authenticate that a user is the proper owner of that token and that the token is securely transmitted to them to avoid an adversary having access to a token he or she does not own.
Solution (a). Correct Token Issuance (Authentication)
Issuing the correct token involves authenticating that we are communicating with the correct user. The authentication process will be based on a user submitting a username and correct password to the group server (over an encrypted channel (solution (b))). The group server will then take the received password, hash it using the SHA-3 hash function, and check it against the hashed password associated with that user stored in our private database. If the hash matches, the user will be transmitted the corresponding token and thus his/her corresponding privileges, if the user provides an incorrect password or username, he/she will be disconnected from the system. 
Solution (b). Secure Token Transmission (Confidentiality and Integrity)
We need a secure channel with which to communicate and authenticate a user. This is because our authentication process (solution (a)) will communicate sensitive information over a public channel that must not be visible nor augmentable by outside parties. To accomplish this we first will implement the Diffie-Hellman (D-H) Secret Key Exchange Protocol to exchange a secret 128 bit session key with the client with which to encrypt our communication over a public channel.


g = agreed upon generator
q = agreed upon prime modulus
b = client’s secret random number
s = server’s secret random number
K = 128 bit AES key

		       Client							Server


Utilizing this shared secret session key, both the client and the server will now use AES with and HMAC (through the GCM mode) to start the authentication process over an encrypted channel. AES is a highly secure CBC-cipher which allows symmetric keys to encrypt communication between two parties. HMAC is a mac address generated with a shared hash function and the contents of the message,  which, when appended to the confidential AES ciphertext, secures the integrity of the transmitted message between the two parties. This will preserve both the confidentiality and integrity of the authentication process.

### T1 (c) Solution Reasoning
We believe that our system aptly mitigates the risks associated with Unauthorized Token Issuance because at each step, confidentiality, integrity, and availability are aptly covered in accordance with contemporary information security standards.
Authenticating users (clients) relies on users having unique user names and secret passwords. If a user has knowledge of both of those pieces, we assume that we have the correct identity and allocate the token. The weakest point in our system would come from users with bad passwords. This can be mitigated by requiring the users to enter a strong password according to our own specifications. Passwords are also unable to be recovered from our side if our system were to be compromised as we have a private database with only the hashes of passwords and not plaintext, thus preserving the user's passwords and foiling any adversary attempt of impersonating a user. We are also operating under the assumption that the group server is trusted and thus the user has the correct address of the server to communicate with.
The authentication process is also protected from passive and active attacks based on the encryption protocols in our communication. The initial interaction is a Diffie-Hellman Key Exchange which allows the server and the client to share a secret key without outsiders ascertaining the key. With that secret key, the client now sends the server his authentication credentials encrypted with AES and backed up integrity-wise by the HMAC. In other words, communication between the server and client will appear completely random to adversaries and if they try to augment it, the server will know. The same goes for the return trip of the token to the user.

## T2: Token Modification/Forgery

Threat Description

If a token is modified by a user, they can increase their access rights and violate established permissions. A modified token could allow an unauthorized user to add themselves to groups they aren’t members of and upload and download files they otherwise wouldn’t have access to. Modified tokens could also allow a user to make themselves the owner of a group, giving them the ability to add or delete users from groups, or entire groups themselves.

Mechanism

To implement protection against token forgery, we can modify our Token class to do two things. First, we can compute a hash of the token’s information and sign it with the GroupServer’s private key, Gp-1. This allows any third party receiving a token to verify the token’s authenticity by verifying the signature using the GroupServer’s public key, Gp.

Then, in our FileServer and GroupServer implementations, anytime a token is received from a client when connecting to a server, the server will extract the signature from the token being passed and pass that signature, along with the username stored in the token to the GroupServer. The GroupServer will then generate a token for that username with the information it already holds, and generate a signature over that new token. If the signature of that newly generated token matches the signature passed by the original token, it will permit the operations. If it does not, it will deny them. Having the GroupServer recompute a token and re-generate the signature will ensure that no contents of the token were modified while the signature remained intact. This verifies not only the signature of the token being passed, but the correctness of the information that token holds.

### Issuance of a Token
1. GroupServer computes a signature of the token with its private key, Gp-1, and passes it to the user
2. The GroupServer then issues the token to the user requesting it
3. The user can verify the signature using the GroupServer’s public key, Gp.

### Ensuring Against Forgery
1. When the FileServer or GroupServer are passed a token to perform an operation, they will first verify the signature by asking GroupServer to compute a new token with the original token’s username. 
2. If the signature over the new token matches that of the original token, it will permit the operation. Otherwise, it will deny it. 

Correctness
This method of ensuring against token forgery is correct with a few assumptions:
1. The GroupServer’s private key has not been compromised
2. The verification of signatures and comparison of tokens are correct
3. The original key exchange was not compromised 

## T3: Unauthorized File Servers 

Threat Description 

Our trust model assumes that properly authenticated file servers are guaranteed to behave as expected. This trust model does not guarantee anything in regards to unauthenticated file servers. An unauthenticated file server may behave unexpectedly or maliciously when handling files, user tokens, etc. For example, an unauthenticated file server may corrupt files within the system. Beyond benign confidentiality and integrity concerns regarding file contents, an adversary could exploit this threat by corrupting files in such a way as to corrupt a user’s machine or even corrupt the entire system. An unauthenticated file server could also be used to leak files to unauthorized users or other entities outside the scope of the system. Finally, an adversary could use an unauthenticated server to steal, view, and modify users tokens. The threats posed by a breach in token integrity has been discussed in previous sections.

<Diagram>


Mechanism

To protect against the threat of malicious file servers, our system must ensure that if a user attempts to contact a file server s, that they actually connect to s and not some other server s’. To accomplish this goal, our system will utilize public key authentication to verify the identity of the server to the user. 

An initial connection from a user to a file server will proceed as follows:
The user contacts the server with an identity verification request
The file server then generates a key pair using 2048-bit RSA
The file server locally stores its private key
The file server then sends its public key back to the user
The user is presented with a message containing the file server’s public key and informed that he should verify that the key belongs to the server to which he is attempting to connect. The user will be prompted to choose whether or not he wishes to continue with the connection
The user verifies the file server’s public key through an outside channel
If the key is successfully verified, then the user will choose to connect, otherwise he will choose to abort the connection
The user will then use the server’s public key to encrypt a challenge randomly generated using the session ID
The server will then decrypt the challenge using its private key
The server will then send the decrypted message back to the user
If the message matches the user’s original challenge, then the server is considered to be authenticated, otherwise the user should close the connection to the server, since it cannot be authenticated
<Once the files server has been authenticated, the user will cache the server’s public key to a trusted keys file???>
<Symmetric key exchange???>
![Alt text](path/to/your/img.png)

Correctness

Our mechanism for addressing the threat of Unauthorized File Servers sufficiently mitigates the threat with a few assumptions:
No entity outside the file server has access to its private key
Upon initial connection, the user will verify the server’s host key by contacting a system administrator through an outside channel 
The user-generated challenge will be sufficiently random/unpredictable and will never be reused

The server can safely send its public key to the user over an insecure public channel because it is of little use to an attacker without the server’s private key. The user can safely send the encrypted challenge to the file server over an insecure public channel without the worry of a replay attack, since an attacker cannot decrypt the challenge without the server’s private key. The server can safely send the decrypted message over the same insecure public channel over which it sent its public key because of preimage resistance. If the decrypted message received by the user from the server matches the original challenge generated by the user, then the server has been authenticated, since only the server has access to its private key, so only it can decrypt the challenge encrypted with its public key. 

## T4: Information Leakage via Passive Monitoring

Threat Description

Our trust model assumes the existence of passive monitoring, and thus all communications need to be hidden from outside observers. Outside observers could discover the contents being communicated during a session, and potentially impersonate participants in the system. Encrypting the contents of all communications using AES and a 128-bit shared session key (exchanged already in T1), ensures that the communications remain private from any observers on the network.

Mechanism

Every communication will be encrypted in AES using the session key exchanged with the user in T1. When passing information from the client, the client will encrypt the information using the shared key, K, and then the server will decrypt that content, with K. This ensures that any information transferred over the network can only be read with the session key K.

There will be three paths of communication: between the client and the GroupServer, the client and a FileServer, and the GroupServer and FileServer (to verify tokens). This means we will do three key exchanges to share three symmetric keys to communicate messages.

Using the shared key from T1 is efficient because only one key needs to be generated per session, and is also secure because if the key is compromised, only one session is compromised, rather than the entire system.

Correctness

Using the shared symmetric key to encrypt sessions is correct under the assumption that the private key is not intercepted, and that the initial exchange in T1 is successful in that no public/private keys have been compromised. Connecting and authenticating as a user is only as secure as that user’s password, so if the user has a strong password, then it will be nearly impossible for someone to impersonate that user by guessing their password to gain access to the system. 
