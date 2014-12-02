CS6238 Project 2 - SSDR
Done by: Yi Ding and Sunny Neo

***********Directories******************
src files are stored in src/
class files are stored in bin/

CA's keystore is located in ./ca.jks
Client's files (keystores and files) are located in client/
Server's files (keystores and files) are located in server/

keytoolcommand.txt are the commands used to generate the public-private key and CSR
before sending it to the CA for signing and importing the signed certificates back
into server's and client's keystores respectively.

**********Requirements*****************
java version "1.8.0_25"

*********Tested on*********************
java version "1.8.0_25"
Java(TM) SE Runtime Environment (build 1.8.0_25-b17)
Java HotSpot(TM) 64-Bit Server VM (build 25.25-b02, mixed mode)

********Execution**********************
server.sh is a script to compile the java codes and to start server 
client1-3.sh is a script to start a client1/client2/client3 to connect to the server

./server.sh
./client1.sh
./client2.sh
./client3.sh



