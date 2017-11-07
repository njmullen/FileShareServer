import java.util.List;
import java.security.*;
import javax.crypto.*;
import org.bouncycastle.jce.provider.*;
import java.security.spec.*;
import java.security.*;
import org.bouncycastle.jcajce.provider.digest.SHA3.DigestSHA3;
import org.bouncycastle.util.encoders.Hex;

/**
 * Interface describing the operations that must be supported by the
 * client application used to talk with the group server.  All methods
 * must be implemented!
 *
 */
public interface GroupClientInterface
{
    /**
     * Connect to the specified group server.  No other methods should
     * work until the client is connected to a group server.
     *
     * @param server The IP address or hostname of the group server
     * @param port The port that the group server is listening on
     *
     * @return true if the connection succeeds, false otherwise
     *
     */
    public boolean connect(final String server, final int port);

    public PublicKey getPublicKey();

    public byte[] sendRandomChallenge(byte[] challenge);

    /**
     * Close down the connection to the group server.
     *
     */
    public void disconnect();

    public boolean checkPassword(String username, String password);
    /**
     * Method used to get a token from the group server.  Right now,
     * there are no security checks.
     *
     * @param username The user whose token is being requested
     *
     * @return A UserToken describing the permissions of "username."
     *         If this user does not exist, a null value will be returned.
     *
     */
    public EncryptedToken getToken(final String username);


    /**
     * Creates a new user.  This method should only succeed if the
     * user invoking it is a member of the special group "ADMIN".
     *
     * @param username The name of the user to create
     * @param token    The token of the user requesting the create operation
     *
     * @return true if the new user was created, false otherwise
     *
     */
    public boolean createUser(final String username, final String password, final EncryptedToken token);


    /**
     * Deletes a user.  This method should only succeed if the user
     * invoking it is a member of the special group "ADMIN".  Deleting
     * a user should also remove him or her from all existing groups.
     *
     * @param username The name of the user to delete
     * @param token    The token of the user requesting the delete operation
     *
     * @return true if the user was deleted, false otherwise
     *
     */
    public boolean deleteUser(final String username, final EncryptedToken token);


    /**
     * Creates a new group.  Any user may create a group, provided
     * that it does not already exist.
     *
     * @param groupname The name of the group to create
     * @param token     The token of the user requesting the create operation
     *
     * @return true if the new group was created, false otherwise
     *
     */
    public boolean createGroup(final String groupname, final EncryptedToken token);


    /**
     * Deletes a group.  This method should only succeed if the user
     * invoking it is the user that originally created the group.
     *
     * @param groupname The name of the group to delete
     * @param token     The token of the user requesting the delete operation
     *
     * @return true if the group was deleted, false otherwise
     *
     */
    public boolean deleteGroup(final String groupname, final EncryptedToken token);


    /**
     * Adds a user to some group.  This method should succeed if
     * the user invoking the operation is the owner of the group.
     *
     * @param user  The user to add
     * @param group The name of the group to which user should be added
     * @param token The token of the user requesting the create operation
     *
     * @return true if the user was added, false otherwise
     *
     */
    public boolean addUserToGroup(final String user, final String group, final EncryptedToken token);


    /**
     * Removes a user from some group.  This method should succeed if
     * the user invoking the operation is the owner of the group.
     *
     * @param user  The name of the user to remove
     * @param group The name of the group from which user should be removed
     * @param token The token of the user requesting the remove operation
     *
     * @return true if the user was removed, false otherwise
     *
     */
    public boolean deleteUserFromGroup(final String user, final String group, final EncryptedToken token);



    /**
     * Lists the members of a group.  This method should only succeed
     * if the user invoking the operation is the owner of the
     * specified group.
     *
     * @param group The group whose membership list is requested
     * @param token The token of the user requesting the list
     *
     * @return A List of group members.  Note that an empty list means
     *         a group has no members, while a null return indicates
     *         an error.
     */
    public List<String> listMembers(final String group, final EncryptedToken token);

}   //-- end interface GroupClientInterface