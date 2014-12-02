import java.io.Serializable;

public class Command implements Serializable {

	private static final long serialVersionUID = -266847514723729983L;
	private String documentUID;
	private byte[] data;
	
	// commandType: GET, PUT, PUT-CONFIDENTIAL, PUT-INTEGRITY, END, SUCCESS, ERROR, DELEGATION
	private String commandType;
	private String commandMsg;
	private DelegationToken token;
	
	
	public Command(String msg, String type) {
		this.documentUID = null;
		this.data = null;
		this.commandMsg = msg;
		this.commandType = type;
		this.token = null;
	}
	
	public Command(String msg, String documentUID, String type) {
		this.documentUID = documentUID;
		this.data = null;
		this.commandMsg = msg;
		this.commandType = type;
		this.token = null;
	}

	public Command(String msg, String documentUID, String type, byte[] data) {
		this.documentUID = documentUID;
		this.data = data;
		this.commandMsg = msg;
		this.commandType = type;
		this.token = null;
	}

	public Command(String msg, String documentUID, String type, byte[] data, DelegationToken token) {
		this.documentUID = documentUID;
		this.data = data;
		this.commandMsg = msg;
		this.commandType = type;
		this.token = token;
	}
	
	 public Command(String documentUID, DelegationToken token) {
		 this.documentUID = documentUID;
		 this.token = token;
	 }
	 
	 public Command(String documentUID, String type, DelegationToken token) {
		 this.commandType = type;
		 this.token = token;
		 this.documentUID = documentUID;
	 }

	public String getDocumentUID() {
		return this.documentUID;
	}

	public byte[] getData() {
		return this.data;
	}

	public String getType() {
		return this.commandType;
	}

	public DelegationToken getToken() {
		return this.token;
	}

	public String getCommandMsg() {
		return commandMsg;
	}

	public void setCommandMsg(String commandMsg) {
		this.commandMsg = commandMsg;
	}

}
