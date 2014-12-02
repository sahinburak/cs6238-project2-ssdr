import java.io.Serializable;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Calendar;

public class DelegationToken implements Serializable, Cloneable {

	private static final long serialVersionUID = -8290320108190481385L;

	

	private Certificate cert;

	private String documentUID;
	private String receiverUID;
	private Rights rights;
	private long ttl;
	private long start;
	private boolean propagationFlag;
	private byte[] tokenSignature;

	public DelegationToken(String documentUID, Certificate issuerCertificate,
			PrivateKey issuerKey, String receiverAlias, Rights rights, long ttl,
			boolean propagationFlag) {

		this.documentUID = documentUID;
		this.cert = issuerCertificate;
		this.receiverUID = receiverAlias;
		this.rights = rights;
		this.ttl = ttl;
		this.start = Calendar.getInstance().getTimeInMillis();
		this.propagationFlag = propagationFlag;
		this.tokenSignature = Util.sign(issuerKey.getEncoded(),
				Util.hash(toString().getBytes()));
	
	}

	public boolean isValid() {
		try {
			byte[] testHash = Util.hash(toString().getBytes());
			return Util.verifySign(this.cert, testHash, this.tokenSignature);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}

	public boolean hasExpired() {
		//System.out.println(start + ":" + ttl + ":" +Calendar.getInstance().getTimeInMillis() );
		return (start + ttl) <= Calendar.getInstance().getTimeInMillis();
	}

	public boolean allowsPropagation(final String documentUID) {
		System.out.println(this.propagationFlag);
		return this.documentUID.equals(documentUID) && this.propagationFlag && !hasExpired() && isValid();
	}

	//propagationflag is not required here i think. because it's not delegation
	//clientUID should not be checked here since it's the token for other client
	//ownerid is already checked before this
	public boolean canGet(final String documentUID) {
		System.out.println("in can get");
		return this.documentUID.equals(documentUID) && ((rights == Rights.GET)|| rights == Rights.BOTH )
				&& !hasExpired() && isValid();
	}

	//propagationflag is not required here i think. because it's not delegation
	//clientUID should not be checked here since it's the token for other client
	//ownerid is already checked before this
	public boolean canPut(final String documentUID) {
		System.out.println(this.documentUID.equals(documentUID));
		System.out.println((rights == Rights.PUT || rights == Rights.BOTH));
		System.out.println(!hasExpired() && isValid());

		return this.documentUID.equals(documentUID) && (rights == Rights.PUT || rights == Rights.BOTH)
				&& !hasExpired() && isValid();
	}

	public String getdocumentUID() {
		return this.documentUID;
	}
	
	public String getIssuerUID() {
		return Util.getSubjectCN(cert);
	}
	
	public String getReceiverUID() {
		return this.receiverUID;
	}

	public String getRights() {
		return this.rights.toString();
	}
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("documentUID=");
		sb.append(documentUID);
		sb.append(";\n");
		sb.append("receiverUID=");
		sb.append(receiverUID);
		sb.append(";\n");
		sb.append("rights");
		sb.append(rights);
		sb.append(";\n");
		sb.append("ttl=");
		sb.append(ttl);
		sb.append(";\n");
		sb.append("start=");
		sb.append(start);
		sb.append(";\n");
		sb.append("propagationFlag=");
		sb.append(propagationFlag);
		sb.append(";\n");
		return sb.toString();
	}
	
	@Override
	protected DelegationToken clone() throws CloneNotSupportedException {
	return (DelegationToken) super.clone();
	}

}
