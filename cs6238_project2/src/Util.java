import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;
public class Util {

	static final int AES_KEYLENGTH = 128; // change this as desired for the
											// security level you want
	static final byte[] iv = new byte[16]; // new to initalize value
	static String keyStorePass = "password";
	static String rootCAAlias = "rootCA";
	static Encoder encoder = Base64.getEncoder();
	static Decoder decoder = Base64.getDecoder();
	
	//KeyStore utilities
	
	public static KeyStore loadKeyStore(String keyStoreFile) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException
	{
		char[] password = keyStorePass.toCharArray();
		FileInputStream in;
		KeyStore ks =null;
	
		in = new FileInputStream(keyStoreFile);
		ks = KeyStore.getInstance("JKS");
		ks.load(in, password);

		return ks;
	}
	
	public static Certificate getCertificate(String keyStoreFile, String alias) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException
	{
		String tempAlias = alias;
		if(!tempAlias.contains("rootCA"))
			tempAlias= alias + "_signed";
		KeyStore ks = loadKeyStore(keyStoreFile);
		Certificate cert = null;
		if (ks != null)
		{
			cert = ks.getCertificate(tempAlias);
		}
		return cert;
	}
	
	public static Key getPrivateKey(String keyStoreFile, String alias) 
	{
		
		KeyStore ks;
		Key privateKey = null;

		try 
		{
			ks = loadKeyStore(keyStoreFile);
			if (ks != null)
			{
				privateKey = ks.getKey(alias, keyStorePass.toCharArray());
			}
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
		return privateKey;
	}
	
	// All the certificate stuff
		//Hardcore ca keystore as ca.jks
		//Hardcore ca certificate alias as "cacert"
		public static boolean verifyCert(Certificate cert) {
			/*
			if(!firstCertValid) {
				firstCertValid = true;
				crlagent = CRLAgent.getInstance();
				crlagent.start();
			}
			*/
			X509Certificate x509Cert = (X509Certificate) cert;
			boolean valid = true;
			try {
				//check dates on the certificate
				x509Cert.checkValidity();
				//load CRL			
				//Verify that the certificate and CRL both were signed by the CA
				X509Certificate rootCACert = (X509Certificate) getCertificate("ca.jks", "rootCA");
				PublicKey caPublicKey = rootCACert.getPublicKey();
				cert.verify(caPublicKey);
				
			} catch (Exception e) {
				valid = false;
				e.printStackTrace();
			}
			return valid;
		}
		
		//get CN from cert
		public static String getSubjectCN(Certificate cert)
		{
			X509Certificate x509cert = (X509Certificate) cert;
			String subjectDN = x509cert.getSubjectDN().getName();
			String[] split = subjectDN.split(",");
		
			return split[0].substring(3);
		}
	
	// Asymmetric Encryption with public key
		public static byte[] encryptASym(Certificate cert, byte[] inputByte) {
			byte[] cipherTextByte = null;
			Key publicKey = null;
			try 
			{		
					if(cert != null)
					{
						publicKey = cert.getPublicKey();
						// Encrypt
						Cipher cipher = Cipher.getInstance("RSA");
						cipher.init(Cipher.ENCRYPT_MODE, publicKey);
						cipherTextByte = cipher.doFinal(inputByte);	
					}
			} 
			catch (Exception e) 
			{
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			return cipherTextByte;
		}

		// Asymmetric Decryption
		// Or Digital Signature?
		public static byte[] decryptASym(byte[] privateKeyByte, byte[] inputByte) {
			byte[] plainTextByte = null;
			try {
				//  and get private key
				Key privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateKeyByte));
				if (privateKey != null) {
					// Decrypt
					Cipher cipher = Cipher.getInstance("RSA");
					cipher.init(Cipher.DECRYPT_MODE, privateKey);
					plainTextByte = cipher.doFinal(inputByte);
				}
				else 
				{
					System.out.println("Nothing found");
				}
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			return plainTextByte;

		}
	
	// AES Symmetric Encryption
	public static byte[] encryptSym(byte[] key, byte[] inputByte) {
		byte[] cipherBytes = null;

		try {
			SecretKey secretKey = new SecretKeySpec(key, "AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));

			cipherBytes = cipher.doFinal(inputByte);

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return cipherBytes;

	}

	// AES Symmetric Decryption
	public static byte[] decryptSym(byte[] key, byte[] inputByte) {
		byte[] plainByte = null;

		try {
			SecretKey secretKey = new SecretKeySpec(key, "AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

			plainByte = cipher.doFinal(inputByte);

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return plainByte;
	}

	

	
	// use to embed file in SecureFile
	public static byte[] serialize(Object obj) {
		ByteArrayOutputStream bos = null;
		ObjectOutputStream oos = null;
		try {
			bos = new ByteArrayOutputStream();
			oos = new ObjectOutputStream(bos);
			oos.writeObject(obj);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return bos.toByteArray();
	}

	public static Object deserialize(byte[] input) {
		Object o = null;
		ByteArrayInputStream bin = null;
		ObjectInputStream ois = null;
		try {
			bin = new ByteArrayInputStream(input);
			ois = new ObjectInputStream(bin);
			o = ois.readObject();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return o;
	}

	public static SecretKey getAESKey() {
//		if (DEBUG)
//			System.out.println("\nStart generating DES key");
		KeyGenerator keyGenerator;
		SecretKey key =null;
		try
		{
			keyGenerator = KeyGenerator.getInstance("AES");
			keyGenerator.init(128);
			key = keyGenerator.generateKey();
			
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}	
		return key;
	}
	
	public static byte[] hash(byte[] data)
	{
		MessageDigest md;
		try {
			
			md = MessageDigest.getInstance("sha1");
			md.update(data);
			return md.digest();

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
		
	}
	
	public static byte[] sign(byte[] privateKeyByte, byte[] inputByte) {
		PrivateKey privateKey;
		byte[] signedBytes = null;
		try {
			privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateKeyByte));
			Signature mySign = Signature.getInstance("MD5withRSA");
		    mySign.initSign(privateKey);
		    mySign.update(inputByte);
		    signedBytes = mySign.sign();
		    
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	    return signedBytes;
	}
	
	public static boolean verifySign(Certificate cert, byte[] inputByte, byte[] signature) {
		
	    PublicKey pubKeySender = cert.getPublicKey();
	    boolean verifySign = false;
	    try {
		    Signature myVerifySign = Signature.getInstance("MD5withRSA");
			myVerifySign.initVerify(pubKeySender);
		    myVerifySign.update(inputByte);
		    verifySign = myVerifySign.verify(signature);

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return verifySign;
		
	}
	
	public static byte[] getSessionKey(byte[] key1, byte[] key2)
	{
		MessageDigest md;
		byte[] combinedKey = null;
		try {
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
			outputStream.write(key1);
			outputStream.write(key2);
			md = MessageDigest.getInstance("md5");
			md.update(outputStream.toByteArray());
			combinedKey = md.digest();

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return combinedKey;
	}
	
	public static void sendSecCommand(byte[] key, ObjectOutputStream out, Command cmd) throws IOException
	{
		byte[] encryptedCommand;
		encryptedCommand = Util.encryptSym(key, Util.serialize(cmd));
		String header = "Cmd:";
		String encoded = new String(encoder.encode(encryptedCommand));
		//out.writeObject(encryptedCommand);
		out.writeObject(header+encoded);

	}
	
	public static void sendSecData(byte[] key, ObjectOutputStream out, byte[] data) throws IOException
	{
		byte[] encryptedData;
		encryptedData = Util.encryptSym(key, data);
		String header = "Data:";
		String encoded = new String(encoder.encode(encryptedData));
//		out.writeObject(encryptedData);
		out.writeObject(header+encoded);
		
		
	}
	public static Object recvSec(byte[] key, ObjectInputStream in) throws IOException, ClassNotFoundException
	{
		String recvString  = (String) in.readObject();
		byte[] encryptedData;
		String encodedCmd;
		byte[] decryptedByte;
		if(recvString.contains("Cmd:")){
//			System.out.println("recv cmd");
			
			encodedCmd = recvString.substring(4);
			
			encryptedData = Util.decoder
					.decode(encodedCmd);
			
			decryptedByte = Util.decryptSym(key, encryptedData);
			
			return deserialize(decryptedByte);		
		}
		
		else if (recvString.contains("Data:")) {
//			System.out.println("recv data");

			encodedCmd = recvString.substring(5);
			encryptedData = Util.decoder
					.decode(encodedCmd);
			decryptedByte = Util.decryptSym(key, encryptedData);
			return decryptedByte;
			
		}
		return null;
	}
	

	
	public static void writeFile(String fileName, Object obj) throws IOException
	{
		FileOutputStream fout = new FileOutputStream(fileName);
		ObjectOutputStream oos = new ObjectOutputStream(fout);
		oos.writeObject(obj);
		fout.close();
		oos.close();
	}
	
	public static Object loadFile(String fileName) throws IOException, ClassNotFoundException
	{
		FileInputStream fin = new FileInputStream(fileName);
		ObjectInputStream ois = new ObjectInputStream(fin);
		Object read = ois.readObject();
		fin.close();
		ois.close();
		return read;
	}
	
	
	public static void main(String[] args) {
		// Symmetric Encryption/Decryption Test
		/*
		byte[] abc = "This is a test haahahaha".getBytes();
		byte[] cipherTextByte = encryptSym(abc, "testtesttesttest");
		String cipherTextString = new String(cipherTextByte);

		byte[] plainTextByte = decryptSym(cipherTextByte, "testtesttesttest");
		String plainTextString = new String(plainTextByte);

		System.out.println("SYMMETRIC EN/DE CRYPTION  TEST");
		System.out.println(new String(abc));
		System.out.println("CIPHERTEXT: " + cipherTextString);
		System.out.println("PLAINTEXT: " + plainTextString);
		System.out.println("SYMMETRIC EN/DE CRYPTION TEST");

		System.out.println("ASYMMETRIC EN/DE CRYPTION  TEST");

		// Asymmetric Encryption/Decryption Test
		cipherTextByte = encryptSym(abc, "client1.jks");
		cipherTextString = new String(cipherTextByte);

		plainTextByte = decryptSym(cipherTextByte, "client1.jks");
		plainTextString = new String(plainTextByte);

		System.out.println(new String(abc));
		System.out.println("CIPHERTEXT: " + cipherTextString);
		System.out.println("PLAINTEXT: " + plainTextString);
		System.out.println("ASYMMETRIC EN/DE CRYPTION  TEST");

		// Test serialize, deserialize
		String a = "helllllo";
		byte[] b = serialize(a);
		System.out.println(a);
		System.out.println(new String(b));
		System.out.println((String) deserialize(b));
		*/

	}
}
