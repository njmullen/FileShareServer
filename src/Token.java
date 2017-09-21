import java.util.List;

/**
 * This class implements the token data structure that will be
 * returned by a group server.  
 */
public class Token implements UserToken {

	private String issuer;
	private String subject;
	private List<String> groups;

	/*
	 * Instansiates a new token that accepts a String for issuer, a String for the 
	 * subject and a List of groups that the owner of this token has access to
	 */
	public Token(String thisIssuer, String thisSubject, List<String> thisGroups){
		this.issuer = thisIssuer;
		this.subject = thisSubject;
		this.groups = thisGroups;
	}

	/**
     * This method should return a string describing the issuer of
     * this token.  This string identifies the group server that
     * created this token.  For instance, if "Alice" requests a token
     * from the group server "Server1", this method will return the
     * string "Server1".
     *
     * @return The issuer of this token
     *
     */
	public String getIssuer(){
		return issuer;
	}

	/**
     * This method should return a string indicating the name of the
     * subject of the token.  For instance, if "Alice" requests a
     * token from the group server "Server1", this method will return
     * the string "Alice".
     *
     * @return The subject of this token
     *
     */
	public String getSubject(){
		return subject;
	}

	/**
     * This method extracts the list of groups that the owner of this
     * token has access to.  If "Alice" is a member of the groups "G1"
     * and "G2" defined at the group server "Server1", this method
     * will return ["G1", "G2"].
     *
     * @return The list of group memberships encoded in this token
     *
     */
	public List<String> getGroups(){
		return groups;
	}

}