import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.security.Key;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class Server {

	String keyStoreFile;
	String alias;
	String password;
	final static String PATH = "server/";
	private static Map<String, ConnectionHandler> clientList;

	// static Map<String,byte[]> clientSession = new HashMap<String, byte[]>();

	public Server() {
		this.keyStoreFile = PATH + "server.jks";
		this.alias = "server";
		this.password = "password";
		Server.clientList = new HashMap<String, ConnectionHandler>();

		// Enable debugging to view the handshake and communication which
		// happens between the SSLClient and the SSLServer
		// System.setProperty("javax.net.debug","all");
		start(1234);

	}

	// Start Server Socket
	public void start(int port) {
		System.out.println("Server Started on port " + port);
		ServerSocket sSocket;
		try {
			sSocket = new ServerSocket(port);
			while (true) {
				Socket clientConnected = (Socket) sSocket.accept();
				Runnable connectionHandler = new ConnectionHandler(
						clientConnected, keyStoreFile, alias);
				new Thread(connectionHandler).start();
			}

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	// To handle each client connected
	private class ConnectionHandler implements Runnable {
		String keyStoreFile;
		String alias;
		Socket socket;
		byte[] sessionKey = null;
		String clientAliasUID;
		int clientPort;
		Certificate serverCert;
		ObjectOutputStream out;
		ObjectInputStream in;

		public ConnectionHandler(Socket socket, String keyStoreFile,
				String alias) {
			this.socket = socket;
			this.keyStoreFile = keyStoreFile;
			this.alias = alias;

			try {
				this.out = new ObjectOutputStream(socket.getOutputStream());
				this.in = new ObjectInputStream(socket.getInputStream());
				this.serverCert = Util.getCertificate(this.keyStoreFile,
						this.alias);
			} catch (Exception e) {
				System.out.println("Error loading Server cert");
			}
		}

		public Socket getSocket() {
			return this.socket;
		}


		public void run() {

			boolean handShakeDone = false;
			try {
				// handshake
				if (handShakeDone != true) {
					System.out.println("Server: starting handshake");
					handShakeDone = handShake(this.out, this.in);
				}
				if (handShakeDone) {
					System.out.println("Server: handshake complete");
					//get client port
					try {
						Command getPort = (Command) Util.recvSec(this.sessionKey, this.in);
						if(getPort.getType().equals("PORT"))
							this.clientPort = Integer.parseInt(getPort.getCommandMsg());
						synchronized (clientList) {
							clientList.put(this.clientAliasUID, this);
						}
					} catch (ClassNotFoundException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
					
					boolean endCommunication = false;
					do {
						Object input = null;
						try {
							// decrypt recv command
							// input = in.readObject();
							input = Util.recvSec(this.sessionKey, this.in);
						} catch (ClassNotFoundException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
						
						/*
						 * Need to send Delegation Token with Commands
						 * delegations.get(documentID);
						 */

						if (input instanceof Command) {
							Command cmd = (Command) input;
							if (cmd.getType().equals("GET")) {
								System.out
										.println("Server: The received command msg is: "
												+ cmd.getCommandMsg());
								String documentUID = cmd.getDocumentUID();

								System.out.println("Server: GET document "
										+ documentUID);

								DelegationToken token = cmd.getToken();
								
								byte[] decryptedData = getData(documentUID,
										token);

								if (decryptedData == null) {
									Util.sendSecCommand(this.sessionKey,
											this.out, new Command(this.alias,
													documentUID, "ERROR"));
								} else {
									Util.sendSecData(this.sessionKey, this.out,
											decryptedData);
								}
							}

							// Server process the PUT-CONFIDENTIAL command
							else if (cmd.getType().equals("PUT-CONFIDENTIAL")) {
								System.out
										.println("Server: The received command msg is: "
												+ cmd.getCommandMsg());
								final String documentUID = cmd.getDocumentUID();
								System.out
										.println("Server: PUT document with encryption "
												+ documentUID);

								final byte[] data = cmd.getData();
								DelegationToken token = cmd.getToken();

								if (putData(documentUID, data, "CONFIDENTIAL",
										token)) {
									Util.sendSecCommand(this.sessionKey,
											this.out, new Command(documentUID,
													"SUCCEED"));
								} else {
									Util.sendSecCommand(this.sessionKey,
											this.out, new Command(documentUID,
													"ERROR"));
								}
							}

							// Server process the PUT-INTEGRITY command
							else if (((Command) input).getType().equals(
									"PUT-INTEGRITY")) {
								System.out
										.println("Server: The received command msg is: "
												+ cmd.getCommandMsg());
								final String documentUID = cmd.getDocumentUID();
								System.out
										.println("Server: PUT document with signature "
												+ documentUID);
								final byte[] data = cmd.getData();
								DelegationToken token = cmd.getToken();

								if (putData(documentUID, data, "INTEGRITY",
										token)) {
									Util.sendSecCommand(this.sessionKey,
											this.out, new Command(documentUID,
													"SUCCEED"));

								} else {
									Util.sendSecCommand(this.sessionKey,
											this.out, new Command(documentUID,
													"ERROR"));
								}
							}

							// Server process the PUT command
							// need to add delegation token
							else if (cmd.equals("PUT")) {
								System.out
										.println("Server: The received command msg is: "
												+ cmd.getCommandMsg());
								String documentUID = cmd.getDocumentUID();
								System.out
										.println("Server: PUT document with no security"
												+ documentUID);
								byte[] data = cmd.getData();
								DelegationToken token = cmd.getToken();

								if (putData(documentUID, data, "NONE", token)) {
									Util.sendSecCommand(this.sessionKey,
											this.out, new Command(documentUID,
													"SUCCEED"));
								} else {
									Util.sendSecCommand(this.sessionKey,
											this.out, new Command(documentUID,
													"ERROR"));
								}
							}

							// get connected Clients
							else if (cmd.getType().equals("CLIENTLIST")) {
								// System.out.println(clientList.keySet().toString());
								synchronized (clientList) {
									Util.sendSecCommand(
											this.sessionKey,
											this.out,
											new Command(
													"",
													"",
													"CLIENTLIST",
													Util.serialize(clientList
															.keySet().toArray())));
								}
							} else if (cmd.getType().equals("VERIFYDELEGATION")) {

								String tempDocUID = cmd.getDocumentUID();
								File doc = getDocument(tempDocUID);
								//System.out.println("In VERIFYDELEGATION");
								//file does not exist
								if (doc == null) {
									System.out.println("ERROR: Document does not exist");
									Util.sendSecCommand(this.sessionKey,
											this.out, new Command("ERROR: Document does not exist",
													"FAILDELEGATION"));
									continue;
								}
								else {
									DelegationToken tempDT = cmd.getToken();
									//has delegate permission
									System.out.println("In CHECKDELEGATION");
									try {
										Document document = null;
										document = getFile(doc);
										// check whether this client can get access to the doc
										// whether client is the owner of the doc
										
										if( this.clientAliasUID.equals(document.getOwnerId()) 	||
												checkDelegation(tempDocUID, tempDT, "DELEGATE") == true) {
											Util.sendSecCommand(this.sessionKey,
													this.out, new Command("Send your delegate Token!",
															"SENDDELEGATION"));
										}
										else {
											Util.sendSecCommand(this.sessionKey,
													this.out, new Command("ERROR: No Delegate Rights!",
															"FAILDELEGATION"));
										}
									} catch (ClassNotFoundException e) {
										// TODO Auto-generated catch block
									}
									
							   }
								
							}
							// Received delegation forwarding request
							else if (cmd.getType().equals("SENDDELEGATION")) {
								DelegationToken dt = cmd.getToken();
								byte[] tempSessionKey = null;
								InetAddress hostname = null;
								Socket tempSocket;
								ObjectOutputStream tempOut = null;
								ObjectInputStream tempIn = null;
								int port =0;

								// check if user has rights to delegate

								// System.out.println(clientList.keySet().toString());
								synchronized (clientList) {
									ConnectionHandler tempCH = clientList.get(dt.getReceiverUID());
									tempSessionKey = tempCH.sessionKey;
									hostname = tempCH.getSocket().getInetAddress();
									port = tempCH.clientPort;
								}
								if (tempSessionKey != null && hostname != null && port !=0) {
									tempSocket = new Socket(hostname, port);
									tempOut = new ObjectOutputStream(
											tempSocket.getOutputStream());
									tempIn = new ObjectInputStream(
											tempSocket.getInputStream());
								} else {
									System.out
											.println("Client has disconnected");
									Util.sendSecCommand(this.sessionKey,
											this.out, new Command("ERROR: Receiver has disconnected",
													"FAILDELEGATION"));
									continue;
								}

								// ObjectOutputStream tempOut =
								// clientList.get(dt.getReceiverUID()).
								Util.sendSecCommand(tempSessionKey, tempOut,
										cmd);
								try {
									Object tempRecv = Util.recvSec(
											tempSessionKey, tempIn);
									if (tempRecv instanceof Command) {
									
										if (((Command) tempRecv).getType()
												.equals("RECVDELEGATION")) {
											System.out.println("Client: "
													+ dt.getReceiverUID()
													+ " Received Delegation!");
											Util.sendSecCommand(this.sessionKey,
													this.out, new Command("Delegate Token Sent Successfully",
															"RECVDELEGATION"));
											continue;
										} else {
											System.out
													.println("ERROR: Send Delegation Failed");
											Util.sendSecCommand(this.sessionKey,
													this.out, new Command("ERROR: Send Delegation Failed",
															"FAILDELEGATION"));
											tempOut.close();
											tempIn.close();
											tempSocket.close();
											continue;
										}
									}
								} catch (ClassNotFoundException e) {
									// TODO Auto-generated catch block
									e.printStackTrace();
									tempOut.close();
									tempIn.close();
									tempSocket.close();
								}

							}

							// Server process the END command
							else if (((Command) input).getType().equals("END")) {
								endCommunication = true;
							}
						} else {
							System.out.println("command error");
							return;
						}

						// Server process the GET command

					} while (!endCommunication);
				}
				this.out.close();
				this.in.close();
				this.socket.close();
				clientList.remove(this.clientAliasUID);
				System.out.println("Server: session terminiated");
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}

		private boolean handShake(ObjectOutputStream out, ObjectInputStream in) {
			Object obj;
			boolean startTLS = false;
			boolean certValid = false;

			Certificate clientCert = null;
			Key serverPrivateKey = null;

			SecretKey serverAESKey = Util.getAESKey();

			SecretKey clientAESKey = null;
			byte[] clientAESKeyDecoded;
			byte[] clientAESKeyByte;

			try {
				serverPrivateKey = Util.getPrivateKey(this.keyStoreFile,
						this.alias);
				while (true) {
					obj = in.readObject();
					if (startTLS == false && obj instanceof String) {
						// System.out.println("Before clientHello");
						String s = (String) obj;
						if (s.equalsIgnoreCase("ClientHello")) {
							out.writeObject(new String("ServerHello"));
							startTLS = true;
						}
					} else if (startTLS == true) {
						// System.out.println("startTLS: True");
						if (obj instanceof Certificate) {
							clientCert = (Certificate) obj;
							if (Util.verifyCert(clientCert)) {
								certValid = true;
								out.writeObject(this.serverCert);

								// send server AES Key
								byte[] serverKeyByte = Util.encryptASym(
										clientCert, serverAESKey.getEncoded());
								String serverKeyString = "Key:"
										+ new String(
												Util.encoder
														.encode(serverKeyByte));
								out.writeObject(serverKeyString);
							}
						}
						if (certValid == true) {
							// System.out.println("CertValid: True");

							if (obj instanceof String) {
								// get server AES Key
								String clientAESKeyString = (String) obj;
								String clientAESKeyEncoded;
								if (clientAESKeyString.contains("Key:")) {
									clientAESKeyEncoded = clientAESKeyString
											.substring(4);
									clientAESKeyDecoded = Util.decoder
											.decode(clientAESKeyEncoded);
									clientAESKeyByte = Util.decryptASym(
											serverPrivateKey.getEncoded(),
											clientAESKeyDecoded);
									clientAESKey = new SecretKeySpec(
											clientAESKeyByte, 0,
											clientAESKeyByte.length, "AES");
								}
								if (serverAESKey != null
										&& clientAESKey != null) {
									this.sessionKey = Util.getSessionKey(
											clientAESKey.getEncoded(),
											serverAESKey.getEncoded());
									System.out.println("Session Key Up");
									String done = "Done:"
											+ new String(
													Util.encoder.encode(Util
															.encryptSym(
																	this.sessionKey,
																	"ServerDone"
																			.getBytes())));
									// System.out.println(done);
									out.writeObject(done);
									this.clientAliasUID = Util
											.getSubjectCN(clientCert);
									// clientSession.put(clientAlias,
									// sessionKey);
									return true;
								}
							}
						}
					}
				}
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			return false;
		}

		private File getDocument(String docUID) {
			final File directory = new File(PATH);
			final File[] files = directory.listFiles();
			File file = null;
			for (File tmpFile : files) {
				if (tmpFile.getName().equals(docUID)) {
					file = tmpFile;
					break;
				}
			}
			return file;
		}

		private Document getFile(File file) throws FileNotFoundException,
				IOException, ClassNotFoundException {
			ObjectInputStream inputStream;
			inputStream = new ObjectInputStream(new FileInputStream(file));
			final Document doc = (Document) inputStream.readObject();
			inputStream.close();
			return doc;
		}

		private Boolean checkDelegation(String documentUID, DelegationToken dt,
				String action) {

			boolean valid = false;
			System.out.println("Check Delegate!");
			// check if document ID = dt.documentID and check session client is
			// the same as token
//			System.out.println(this.clientAliasUID + ":" + dt.getReceiverUID());
//			System.out.println(documentUID + ":" + dt.getdocumentUID());

			if(dt != null) {
				if (documentUID.equals(dt.getdocumentUID())
						&& this.clientAliasUID.equals(dt.getReceiverUID())) {
					if (action.equals("GET")) {
						valid = dt.canGet(documentUID);
						System.out.println(valid);
					} else if (action.equals("PUT")) {
						valid = dt.canPut(documentUID);
					} else if (action.equals("DELEGATE")) {
						valid = dt.allowsPropagation(documentUID);
					}
				}
			}
			
			return valid;
		}

		private byte[] getData(final String documentUID,
				final DelegationToken dt) {
			// check whether this doc exists
			File doc = getDocument(documentUID);
			if (doc != null) {
				try {
					// this document exists
					Document document = getFile(doc);

					// check whether this client can get access to the doc
					// whether client is the owner of the doc
					if (this.clientAliasUID.equals(document.getOwnerId())) {
						return getDecryptedData(document);
					} 
					// not the owner
					// has delegation token
					else if (dt != null
							&& checkDelegation(documentUID, dt, "GET"))
						return getDecryptedData(document);
					else {
						System.out
								.println("The client is not the owner of the file, access denied!");
						return null;
					}
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
			return null;
		}

		private byte[] getDecryptedData(final Document document)
				throws Exception {
			byte[] data = null;

			String flag = document.getFlag();
			Key privateKey = Util.getPrivateKey(this.keyStoreFile, this.alias);
			byte[] documentHash;
			byte[] documentKey = Util.decryptASym(privateKey.getEncoded(),
					document.getKey());
			;
			byte[] reconstructHash;

			if (flag.equals("CONFIDENTIAL")) {
				data = Util.decryptSym(documentKey, document.getData());
			} else if (flag.equals("INTEGRITY")) {
				documentHash = Util.decryptASym(privateKey.getEncoded(),
						document.getHash());

				reconstructHash = Util.hash(document.getData());
				// System.out.println("Old hash " + new String(documentHash));
				// System.out.println("New hash " + new
				// String(reconstructHash));

				if (Arrays.equals(documentHash, reconstructHash)) {
					data = document.getData();
				} else {
					System.out.println("File integrity is compromised");
					return null;
				}
			} else
				data = document.getData();

			return data;
		}

		private boolean putData(String documentUID, byte[] data,
				String securityFlag, DelegationToken dt) {

			boolean result = false;
			byte[] hash;
			Document newDoc = null;

			final File doc = getDocument(documentUID);

			// doc does not exist, put is permitted
			// create new doc under the current client's uid
			
			if (doc == null) {
				newDoc = new Document(this.clientAliasUID);
				System.out.println("file does not exist");
			}
			
			//if doc exist
			// and no token, check ownerid
			// if token exists check ownerid and token issuer 
			else if (doc != null) {
				try {
					System.out.println("file exist");

					newDoc = getFile(doc);
				
					if(dt == null ) {
						if(!this.clientAliasUID.equals(newDoc.getOwnerId())) {
							System.out.println("check ownerid");
							return false;
						}
					}
					else {
						if(!dt.getIssuerUID().equals(newDoc.getOwnerId()) || 
								!checkDelegation(documentUID, dt, "PUT")) {
							System.out.println("check token");
							return false;
						}
					}
				} catch (FileNotFoundException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (ClassNotFoundException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
			}

			System.out.println("In Processing PUT");
			SecretKey randomAESKey = Util.getAESKey();
			byte[] documentKey = Util.encryptASym(this.serverCert,
					randomAESKey.getEncoded());
			newDoc.setKey(documentKey);

			byte[] processedData = data.clone();
			try {
				if (securityFlag.equals("CONFIDENTIAL")) {
					// do encryption of the file
					processedData = Util.encryptSym(randomAESKey.getEncoded(),
							data);
					newDoc.setFlag("CONFIDENTIAL");

				} else if (securityFlag.equals("INTEGRITY")) {
					// do signature of the document
					newDoc.setFlag("INTEGRITY");
					hash = Util.encryptASym(this.serverCert,
							Util.hash(processedData));
					newDoc.setHash(hash);

				} else if (securityFlag.equals("NONE")) {
					// put file without security
					// processedData initalized at the start
					newDoc.setFlag("NONE");
				}
				newDoc.setData(processedData);
				Util.writeFile(PATH + documentUID, newDoc);
				result = true;

			} catch (Exception e) {
				result = false;
				System.out.println("ERROR: PUTTING FILE");
			}
			return result;
		}
	}

	public static void main(String[] args) {
		Server startServer = new Server();
	}
}
