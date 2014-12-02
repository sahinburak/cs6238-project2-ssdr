import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.Scanner;
import java.net.ServerSocket;
import java.net.Socket;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Client {

	private String keyStoreFile;
	private String alias;
	private String serverName;
	private String password;
	private Certificate clientCert = null;
	private byte[] sessionKey;
	private boolean handShakeDone;
	private transient Socket socket;
	private transient ObjectOutputStream out;
	private transient ObjectInputStream in;
	final static String PATH = "client/";
	private Map<String, DelegationToken> delegations;
	final int PORT;
	private int runListener;
	
	

	public Client(String keyStoreFile, String alias) {
		// Specifying the Keystore for client's private key to be loaded
		Random r = new Random();
		int max=60000;
		int min=2000; 
		PORT = r.nextInt(max - min + 1) + min;
		this.keyStoreFile = PATH + keyStoreFile;
		this.alias = alias;
		this.password = "password";
		this.socket = null;
		this.out = null;
		this.in = null;
		this.handShakeDone = false;
		try {
			//this.delegations = loadDelegationFile();
			this.delegations = new HashMap<String, DelegationToken>();
			this.clientCert = Util.getCertificate(this.keyStoreFile, this.alias);
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			//e.printStackTrace();

		}

	}

	// Connect to Server
	public void startSession(String hostName) {
 		int serverPort = 1234; // Port where the SSL Server is listening
		try {
			// Creating Client Sockets
			socket = new Socket(hostName, serverPort);

			// Initializing the streams for Communication with the Server
			this.out = new ObjectOutputStream(socket.getOutputStream());
			this.in = new ObjectInputStream(socket.getInputStream());

			if (this.handShakeDone != true) {
				this.handShakeDone = handShake(out, in);
			}
			if (this.handShakeDone == true) {
				Util.sendSecCommand(this.sessionKey, this.out, 
						new Command(Integer.toString(PORT), "PORT" ));
				startDelegateListener();
				menu();
			}
		} catch (Exception exp) {
			System.out.println("Client: Exception occurred .... " + exp);
			exp.printStackTrace();
		}

	}

	private void menu() {
		
		Scanner sc = new Scanner(System.in);
		int userInput = 0;
		do {
			System.out.println("Welcome " + this.alias);
			System.out.println("1. Get Document");
			System.out.println("2. Put Document");
			System.out.println("3. Delegate Rights");
			System.out.println("4. End Session");
			try {
				String input = sc.nextLine();
				userInput = Integer.parseInt(input);
				if (userInput < 1 || userInput > 5) {
					System.out.println("Invalid Option. Please try again.");
					continue;
				}
			} catch (Exception e) {
				System.out.println("Invalid Option. Please try again.");
				continue;
			}

			String docUID = "";
			String receiverAlias = "";
			int securityFlagInt = 0;
			boolean propagationFlag = false;
			String securityFlag = null;
			long ttl = 0;

			switch (userInput) {
			case 1:
				System.out.println("Please enter Document UID: ");
				docUID = sc.nextLine();
				get(docUID);
				break;

			case 2:
				System.out.println("Please enter Document UID: ");
				docUID = sc.nextLine();

				System.out.println("Select Security Flag: ");
				System.out.println("1. CONFIDENTIAL");
				System.out.println("2. INTEGRITY");
				System.out.println("3. None");
				try {
					String input = sc.nextLine();
					securityFlagInt = Integer.parseInt(input);
					if (securityFlagInt < 1 || securityFlagInt > 3) {
						System.out.println("Invalid Option. Please try again.");
						continue;
					}
					if (securityFlagInt == 1) {
						securityFlag = "CONFIDENTIAL";
					}

					else if (securityFlagInt == 2) {
						securityFlag = "INTEGRITY";
					}

					else if (securityFlagInt == 3) {
						securityFlag = "NONE";
					}
				} catch (Exception e) {
					System.out.println("Invalid Option. Please try again.");
					continue;
				}

				put(docUID, securityFlag);
				break;
			// /////////////////////
			// /////////////////////////////////////////////////////////////////////////////////////////////////
			case 3:
				String[] clients = null;
				boolean correctAlias = false;
				boolean allClients = false;
				System.out.println("Please enter Document UID: ");
				docUID = sc.nextLine();

				// client
				try {
					Util.sendSecCommand(this.sessionKey, this.out, new Command(
							"", "CLIENTLIST"));
					Object recvClientList = Util.recvSec(this.sessionKey,
							this.in);

					if (recvClientList instanceof Command) {
						Command cmd = (Command) recvClientList;
						if (cmd.getType().equals("CLIENTLIST")) {

							Object[] tempClients = (Object[]) Util
									.deserialize(cmd.getData());
							clients = Arrays.copyOf(tempClients,
									tempClients.length, String[].class);

							if (clients != null) {
								int i = 1;
								for (String c : clients) {
									if(c.equals(this.alias))
										continue;
									System.out.println(i + ". " + c);
									i++;
								}
								System.out.println(i + ". " + "ALL");
							}
						}
					}

					System.out.println("Please enter receiver's alias: ");
					receiverAlias = sc.nextLine();

					if (receiverAlias.equals("ALL")) {
						correctAlias = true;
						allClients = true;
					} else {
						for (String c : clients) {
							if (c.equals(receiverAlias)) {
								correctAlias = true;
								break;
							}
						}
					}

					if (correctAlias == false) {
						System.out.println("Invalid receiver alias. ");
						continue;
					}

					// time
					System.out.println("Please enter duration(minutes): ");
					try {
						String input = sc.nextLine();
						ttl = Integer.parseInt(input) * 60 * 1000;
					} catch (Exception e) {
						System.out.println("Invalid Input. Please try again");
						continue;
					}
					System.out.println("Select Rights: ");
					System.out.println("1. Get only.");
					System.out.println("2. Put only.");
					System.out.println("3. Both.");
					String tempRights = sc.nextLine();
					Rights rights;
					if (tempRights.equals("1")) {
						rights = Rights.GET;
					} else if (tempRights.equals("2")) {
						rights = Rights.PUT;
					} else if (tempRights.equals("3")) {
						rights = Rights.BOTH;
					} else {
						System.out.println("Invalid Option. Please try again.");
						continue;
					}

					System.out.println("Select Propagation Flag: ");
					System.out.println("1. Disallow Propagation.");
					System.out.println("2. Permit Propagation.");
					String flag = sc.nextLine();

					if (flag.equals("1")) {
						propagationFlag = false;
					} else if (flag.equals("2")) {
						propagationFlag = true;
					} else {
						System.out.println("Invalid Option. Please try again.");
						continue;
					}
					if(allClients == true) {
						for (String eachReceiverAlias : clients) {
							if(eachReceiverAlias.equals(this.alias)) {
								continue;
							}
							delegate(docUID, eachReceiverAlias, rights, ttl,
									propagationFlag);
						}
					}
					else {
					delegate(docUID, receiverAlias, rights, ttl,
							propagationFlag);
					}
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (ClassNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (KeyStoreException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (NoSuchAlgorithmException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (CertificateException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				break;
				
			case 4: break;
			case 5:
				synchronized (this.delegations) {
					System.out.println(this.delegations.toString());
				}
				break;
			// ////////////////////
			// ///////////////////////////////////////////////////////////////////////////////////////////////////
			default:
				System.out.println("Invalid Option");
				break;
			}
		} while (userInput != 4);
		endSession();
		runListener = 0;
		sc.close();
		System.exit(0);

	}

	private boolean handShake(ObjectOutputStream out, ObjectInputStream in) {
		Object obj;
		boolean startTLS = false;
		boolean certValid = false;
		boolean handShakeSucc = false;
		Certificate serverCert = null;
		Key clientPrivateKey = null;

		SecretKey serverAESKey = null;
		SecretKey clientAESKey = Util.getAESKey();
		byte[] serverAESKeyDecoded;
		byte[] serverAESKeyByte;

		// Encoder encoder = Base64.getEncoder();
		// Decoder decoder = Base64.getDecoder();
		try {
			clientPrivateKey = Util
					.getPrivateKey(this.keyStoreFile, this.alias);
			
			while (true) {
				if (startTLS == false) {
					out.writeObject(new String("ClientHello"));
				}
				obj = in.readObject();
				if (obj != null) {
					if (startTLS == false && obj instanceof String) {
						String s = (String) obj;
						if (s.equalsIgnoreCase("ServerHello")) {
							out.writeObject(this.clientCert);
							startTLS = true;
						}
					}

					else if (startTLS == true) {
						// System.out.println("startTLS: True");
						if (obj instanceof Certificate) {
							serverCert = (Certificate) obj;
							if (Util.verifyCert(serverCert)) {
								certValid = true;
								// send client AES Key
								byte[] clientKeyByte = Util.encryptASym(
										serverCert, clientAESKey.getEncoded());
								String clientKeyString = "Key:"
										+ new String(
												Util.encoder
														.encode(clientKeyByte));
								out.writeObject(clientKeyString);

							}
						}
						if (certValid == true) {
							// System.out.println("CertValid: True");
							if (this.sessionKey == null) {
								if (obj instanceof String) {
									// get server AES Key
									String serverAESKeyString = (String) obj;
									String serverAESKeyEncoded;
									if (serverAESKeyString.contains("Key:")) {
										serverAESKeyEncoded = serverAESKeyString
												.substring(4);
										serverAESKeyDecoded = Util.decoder
												.decode(serverAESKeyEncoded);

										serverAESKeyByte = Util.decryptASym(
												clientPrivateKey.getEncoded(),
												serverAESKeyDecoded);
										serverAESKey = new SecretKeySpec(
												serverAESKeyByte, 0,
												serverAESKeyByte.length, "AES");
									}
									if (serverAESKey != null
											&& clientAESKey != null) {
										this.sessionKey = Util.getSessionKey(
												clientAESKey.getEncoded(),
												serverAESKey.getEncoded());
										System.out
												.println("Client: Session Key Up");

									}
								}
							} else {
								String done = (String) obj;
								if (done.contains("Done:")) {
									done = done.substring(5);
									byte[] doneDecoded = Util.decoder
											.decode(done);
									byte[] doneDecrypted = Util.decryptSym(
											this.sessionKey, doneDecoded);
									String doneDecryptedString = new String(
											doneDecrypted);
									if (doneDecryptedString
											.equals("ServerDone"))
										return true;
									else
										return false;
								}

							}
						}
					}
				}
			}
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return handShakeSucc;

		}
	}

	public void endSession() {
		// Closing the Streams and the Socket
		try {
			Command cmd = new Command("", "END");
			Util.sendSecCommand(this.sessionKey, this.out, cmd);
			this.out.close();
			this.in.close();
			this.socket.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	// Todo: Send Token with Command
	public void get(final String UID) {
		System.out.println("Client: Getting document " + UID);
		Command command;
		DelegationToken token = getToken(UID);
		//System.out.println(token.toString());
		
		if (token != null && token.canGet(UID)) {
			System.out.println("sent with token");
			command = new Command(UID, "GET", token);
		} else {
			command = new Command("Getting document", UID, "GET");
		}

		try {
			// got to encrypt here
			Util.sendSecCommand(this.sessionKey, this.out, command);
			// got to decrypt here
			final Object msg = Util.recvSec(this.sessionKey, this.in);

			if (msg instanceof Command) {
				System.out.println("In GET msg command ");
				final Command cmd = (Command) msg;

				if (cmd.getType().equals("ERROR")) {
					final String cmdMsg = cmd.getCommandMsg();
					System.out
							.println("Client: Document GET error on server : "
									+ cmdMsg);
				} else {
					System.out
							.println("Client: I don't understand your command.");
				}

			} else if (msg instanceof byte[]) {
				final byte[] returnfile = (byte[]) msg;
				final FileOutputStream fos = new FileOutputStream(PATH + UID);
				fos.write(returnfile);
				fos.close();
				System.out.println("Client: File GET Ok: " + UID);
			}

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	// Todo: Send Token with Command
	public void put(String UID, String securityFlag) {
		System.out.println("Client: Putting document " + UID);
		try {
			final File file = new File(PATH + UID);
			final BufferedInputStream bis = new BufferedInputStream(
					new FileInputStream(file));
			final byte[] data = new byte[(int) file.length()];
			bis.read(data);
			bis.close();

			Command cmd;
			DelegationToken token = getToken(UID);
			
			// delegation
			if (token != null && token.canPut(UID)) {
				if (securityFlag == "CONFIDENTIAL") {
					cmd = new Command(
							"Client: Putting document with encryption", UID,
							"PUT-CONFIDENTIAL", data, token);
				} else if (securityFlag == "INTEGRITY") {
					cmd = new Command(
							"Client: Putting document with signature", UID,
							"PUT-INTEGRITY", data, token);
				} else {
					cmd = new Command(
							"Client: Putting document with no security", UID,
							"PUT", data, token);
				}
			}

			// no delegation
			else {
				if (securityFlag == "CONFIDENTIAL") {
					cmd = new Command(
							"Client: Putting document with encryption", UID,
							"PUT-CONFIDENTIAL", data);
				} else if (securityFlag == "INTEGRITY") {
					cmd = new Command(
							"Client: Putting document with signature", UID,
							"PUT-INTEGRITY", data);
				} else {
					cmd = new Command(
							"Client: Putting document with no security", UID,
							"PUT", data);
				}
			}

			// encrypt and send command
			Util.sendSecCommand(this.sessionKey, this.out, cmd);

			// decrypt
			final Object msg = Util.recvSec(this.sessionKey, this.in);

			if (msg instanceof Command) {
				String cmdType = ((Command) msg).getType();
				// System.out.println("In Put:" + cmdType);
				if (cmdType.equals("ERROR")) {
					System.out.println("Client: File PUT error : "
							+ ((Command) msg).getCommandMsg());
				} else if (cmdType.equals("SUCCEED")) {
					System.out.println("Client: File PUT succeed : "
							+ ((Command) msg).getCommandMsg());
				} else {
					System.out
							.println("Client: I don't understand your command");
				}

			} else {
				System.out
						.println("Client: The returned value is not a command!");
			}

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	// /////////////////////////////////////////////////////////////////////////////////////////////
	public void delegate(String UID, String receiverAlias, Rights rights,
			long ttl, boolean propagationFlag) throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException, IOException {

		PrivateKey clientPrivateKey = (PrivateKey) Util.getPrivateKey(
				this.keyStoreFile, this.alias);
		Certificate clientCert = Util.getCertificate(this.keyStoreFile,
				this.alias);
		DelegationToken selfDT = delegations.get(UID);
		
		//check verify and delegation permission
		Util.sendSecCommand(this.sessionKey, this.out, new Command(
				UID, "VERIFYDELEGATION", selfDT));
		Object recvObj;
		try {
			recvObj = Util.recvSec(this.sessionKey, this.in);
			//check if server says it's ok to send delegation token
			if (recvObj instanceof Command) {
				Command cmd = (Command) recvObj;
				
				if (cmd.getType().equals("SENDDELEGATION")) {
					DelegationToken dt = new DelegationToken(UID, clientCert,
							clientPrivateKey, receiverAlias, rights, ttl,
							propagationFlag);
					Util.sendSecCommand(this.sessionKey, this.out, new Command(UID,
							"SENDDELEGATION", dt));
					recvObj = Util.recvSec(this.sessionKey, this.in);
					
					if (recvObj instanceof Command) {
						cmd = (Command) recvObj;
						
						if (cmd.getType().equals("RECVDELEGATION")) {
							System.out.println("Delegation Token successfully sent to :" + receiverAlias);
						}
						else if (cmd.getType().equals("FAILDELEGATION")) {
							System.out.println(cmd.getCommandMsg());
						}
				}
			  }
		  }
	   } catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public DelegationToken getToken(final String UID) {
		DelegationToken token;
		for(String c : delegations.keySet()) { 
			if(c.equals(UID)) {				
				try {
					token = delegations.get(c).clone();
					return token;
				} catch (CloneNotSupportedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
		return null;
	}
	
	// //////////////////////////////////////////////////////////////////////////////////////////////
	public void startDelegateListener() {
		Runnable listener = new Listener();
		new Thread(listener).start();
		this.runListener = 1;
	}

	
	

	private class Listener implements Runnable {

		ServerSocket serverSocket;
	
		public Listener() {
		}

		public void run() {
			try {
				this.serverSocket = new ServerSocket(PORT);
				while (runListener==1) {
					Socket serverConnected = (Socket) serverSocket.accept();
					Runnable connectionHandler = new ConnectionHandler(
							serverConnected);
					new Thread(connectionHandler).start();
				}

			} catch (Exception e) {
				e.printStackTrace();
			}

		}
	}

	private class ConnectionHandler implements Runnable {
		Socket socket;
		ObjectOutputStream out;
		ObjectInputStream in;

		public ConnectionHandler(Socket s) {
			this.socket = s;

			try {
				this.out = new ObjectOutputStream(socket.getOutputStream());
				this.in = new ObjectInputStream(socket.getInputStream());
				// this.serverCert = Util.getCertificate(this.keyStoreFile,
				// this.alias);
			} catch (Exception e) {
				// System.out.println("Error loading Server cert");
			}
		}

		public void run() {
			Object recvObject;
			while (true) {
				try {
					recvObject = Util.recvSec(sessionKey, this.in);
					if (recvObject instanceof Command) {
						Command cmd = (Command) recvObject;
						if (cmd.getType().equals("SENDDELEGATION")) {
							DelegationToken dt = cmd.getToken();
							synchronized(delegations) {
								delegations.put(dt.getdocumentUID(), dt);
								//System.out.println(dt.getdocumentUID());
							}
							System.out.println("Received Token from : " + dt.getIssuerUID() 
									+ "\nfor Document: " + dt.getdocumentUID() 
											+ "\nRights: " + dt.getRights());
						}
						Util.sendSecCommand(sessionKey, this.out,
								new Command("", "RECVDELEGATION"));
						break;

					}

					this.out.close();
					this.in.close();
					this.socket.close();
				} catch (ClassNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}

	}

	public static void main(String[] args) {
		if (args.length == 0) {
			System.out.println("./client.sh clientalias");
			return;
		}
		Client c = new Client(args[0] + ".jks", args[0]);

//		Client c = new Client("client2.jks", "client2");
//		Client c = new Client("client1.jks", "client1");
		//Client c = new Client("client3.jks", "client1");
		c.startSession("localhost");
		// c.startSession();

	}

}
