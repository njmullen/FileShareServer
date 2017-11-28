public class ShareFile implements java.io.Serializable, Comparable<ShareFile> {

	/**
	 *
	 */
	private static final long serialVersionUID = -6699986336399821598L;
	private String group;
	private String path;
	private String owner;
	private byte[] keyedHash;

	public ShareFile(String _owner, String _group, String _path, byte[] _keyedHash) {
		group = _group;
		owner = _owner;
		path = _path;
		keyedHash = _keyedHash;
	}

	public String getPath()
	{
		return path;
	}

	public String getOwner()
	{
		return owner;
	}

	public String getGroup() {
		return group;
	}

	public byte[] getKeyedHash() {
		return keyedHash;
	}

	public int compareTo(ShareFile rhs) {
		if (path.compareTo(rhs.getPath())==0)return 0;
		else if (path.compareTo(rhs.getPath())<0) return -1;
		else return 1;
	}

}
