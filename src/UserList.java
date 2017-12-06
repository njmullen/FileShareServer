/* This list represents the users on the server */
import java.util.*;
import java.security.*;
import org.bouncycastle.jcajce.provider.digest.SHA3.DigestSHA3;
import org.bouncycastle.util.encoders.Hex;


	public class UserList implements java.io.Serializable {
	
		/**
		 * 
		 */
		private static final long serialVersionUID = 7600343803563417992L;
		private Hashtable<String, User> list = new Hashtable<String, User>();
		
		public synchronized void addUser(String username, byte[] password, byte[] salt)
		{
			User newUser = new User();

  			newUser.setPassword(password);
  			newUser.setSalt(salt);

			list.put(username, newUser);
		}

		public byte[] getPassword(String username){
			return list.get(username).getPassword();
		}

		public byte[] getSalt(String username){
			return list.get(username).getSalt();
		}

		public byte[] getY(String username){
			return list.get(username).getY();
		}

		public void setY(String username, byte[] y){
			list.get(username).setY(y);
		}

		public int getChallengeLevel(String username){
			return list.get(username).getChallengeLevel();
		}

		public void resetFailedAttempts(String username){
			list.get(username).resetFailedAttempts();
		}

		public void addFailedAttempt(String username){
			list.get(username).addFailedAttempt();
		}
		
		public synchronized void deleteUser(String username)
		{
			list.remove(username);
		}
		
		public synchronized boolean checkUser(String username)
		{
			if(list.containsKey(username))
			{
				return true;
			}
			else
			{
				return false;
			}
		}

		//Returns the list of users
		public synchronized Enumeration<String> getUserList(){
			return list.keys();
		}
		
		public synchronized ArrayList<String> getUserGroups(String username)
		{
			return list.get(username).getGroups();
		}
		
		public synchronized ArrayList<String> getUserOwnership(String username)
		{
			return list.get(username).getOwnership();
		}
		
		public synchronized void addGroup(String user, String groupname)
		{
			list.get(user).addGroup(groupname);
		}
		
		public synchronized void removeGroup(String user, String groupname)
		{
			list.get(user).removeGroup(groupname);
		}
		
		public synchronized void addOwnership(String user, String groupname)
		{
			list.get(user).addOwnership(groupname);
		}
		
		public synchronized void removeOwnership(String user, String groupname)
		{
			list.get(user).removeOwnership(groupname);
		}
		
	
	class User implements java.io.Serializable {

		/**
		 * 
		 */
		private static final long serialVersionUID = -6699986336399821598L;
		private ArrayList<String> groups;
		private ArrayList<String> ownership;
		private byte[] password;
		private byte[] salt;
		private int failedAttempts;
		private byte[] y;
		
		public User()
		{
			groups = new ArrayList<String>();
			ownership = new ArrayList<String>();
		}

		public void resetFailedAttempts(){
			this.failedAttempts = 0;
		}

		public void addFailedAttempt(){
			this.failedAttempts++;
		}

		public int getChallengeLevel(){
			if(failedAttempts < 5){
				return 0;
			} else if (failedAttempts >= 5 && failedAttempts < 10){
				return 1;
			} else {
				return 2;
			}
		}

		public byte[] getY(){
			return this.y;
		}

		public void setY(byte[] yT){
			this.y = yT;
		}

		public void setPassword(byte[] passwordHash){
			this.password = passwordHash;
		}

		public byte[] getPassword(){
			return password;
		}

		public void setSalt(byte[] salt){
			this.salt = salt;
		}

		public byte[] getSalt(){
			return salt;
		}
		
		public ArrayList<String> getGroups()
		{
			return groups;
		}
		
		public ArrayList<String> getOwnership()
		{
			return ownership;
		}
		
		public void addGroup(String group)
		{
			groups.add(group);
		}
		
		public void removeGroup(String group)
		{
			if(!groups.isEmpty())
			{
				if(groups.contains(group))
				{
					groups.remove(groups.indexOf(group));
				}
			}
		}
		
		public void addOwnership(String group)
		{
			ownership.add(group);
		}
		
		public void removeOwnership(String group)
		{
			if(!ownership.isEmpty())
			{
				if(ownership.contains(group))
				{
					ownership.remove(ownership.indexOf(group));
				}
			}
		}
		
	}
	
}	
