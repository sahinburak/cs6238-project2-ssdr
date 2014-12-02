import java.io.*;

public class Document implements Serializable {

	private static final long serialVersionUID = -6523254778307822965L;
	private String ownerId;
	private byte[] hash;
	// data is the file data, either encrypted or not
	private byte[] data;
	private byte[] key;
	private String flag;

	
	public Document(final String ownerId) {
		this.ownerId = ownerId;
		
	}
	public Document(final String ownerId, final byte[] data) {
		this.ownerId = ownerId;
		this.data = data.clone();
	}

	public String getOwnerId() {
		return ownerId;
	}

	public void setOwnerId(final String ownerId) {
		this.ownerId = ownerId;
	}

	// The owner has get/put access
	// For delegation, delegator will be set with id = userId
	public boolean hasGetAccess(final String userId) {
		return this.ownerId.equals(userId);
	}

	public boolean hasPutAccess(final String userId) {
		return this.ownerId.equals(userId);
	}

	public void setData(final byte[] data) {
		this.data = data.clone();
	}

	public byte[] getHash() {
		return hash.clone();
	}

	public void setHash(final byte[] hash) {
		this.hash = hash.clone();
	}

	public byte[] getData() {
		return this.data.clone();
	}

	public byte[] getKey() {
		return key;
	}
	public void setKey(byte[] key) {
		this.key = key.clone();
	}
	public String getFlag() {
		return flag;
	}
	public void setFlag(String flag) {
		this.flag = flag;
	}
}
