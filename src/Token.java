import java.util.ArrayList;
import java.util.List;


public class Token implements UserToken, java.io.Serializable {

  String issuer;
  String userName;
  List<String> groups;
  String fileServerName;
  int fileServerPort;

  public Token(String server, String userName, List<String> groups, String serverName, int portNumber){
    issuer = server;
    this.userName = userName;
    this.groups = groups;
    this.fileServerName = serverName;
    this.fileServerPort = portNumber;
  }

  public Token(byte[] tokenString){
    StringBuilder sb = new StringBuilder();
    String _issuer = " ";
    String _userName = " ";
    String _fileServer = " ";
    String _filePort = " ";
    List<String> _groups = new ArrayList<String>();

    char c = ' ';
    int numPipe = 0;

    for(int i = 0; i < tokenString.length; i++){
      c = (char) tokenString[i];

      if(c == '|'){
        numPipe++;

        if(numPipe == 1){
          _userName = sb.toString();
        }

        else if(numPipe == 2){
          _issuer = sb.toString();
        }

        else if (numPipe == 3){
          _fileServer = sb.toString();
        }

        else if (numPipe == 4){
          _filePort = sb.toString();
        }

        else{
          _groups.add(sb.toString());
        }

        sb = new StringBuilder();
      }
      else{
        sb.append(c);
      }
    }

    issuer = _issuer;
    userName = _userName;
    groups = _groups;
    fileServerName = _fileServer;
    fileServerPort = Integer.parseInt(_filePort);
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
  public String getIssuer(){return issuer;}


  /**
   * This method should return a string indicating the name of the
   * subject of the token.  For instance, if "Alice" requests a
   * token from the group server "Server1", this method will return
   * the string "Alice".
   *
   * @return The subject of this token
   *
   */
  public String getSubject() {return userName;}

  public String getFileServer() {return fileServerName;}

  public int getFilePort() {return fileServerPort;}


  /**
   * This method extracts the list of groups that the owner of this
   * token has access to.  If "Alice" is a member of the groups "G1"
   * and "G2" defined at the group server "Server1", this method
   * will return ["G1", "G2"].
   *
   * @return The list of group memberships encoded in this token
   *
   */
  public List<String> getGroups() {return groups;}

  public byte[] getTokenString(){
      StringBuilder sb = new StringBuilder();
      sb.append(userName);
      sb.append("|");
      sb.append(issuer);
      sb.append("|");
      sb.append(fileServerName);
      sb.append("|");
      sb.append(fileServerPort);
      sb.append("|");
      for (int i = 0; i < groups.size(); i++){
        sb.append(groups.get(i));
        sb.append("|");
      }
      String tokenString = sb.toString();
      return tokenString.getBytes();
  }

}
