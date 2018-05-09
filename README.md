CAU client (version mF2c IT1 demo)

This application supports the agent registration process.  It is triggered by the Policy block to obtain an agent certificate from the mF2C fog CA via a TLS1.2 TCP-IP call to the regional CAU.  Then it validates the newly minted agent certificate with the leader agent via a TLS handshake with the leader agent CAU and caches the public key returned from the process to secure future communication. 

For the IT1 demo, the socket server runs on 0.0.0.0:46065.  Both the CAU and leader CAU ip:port are expected to be passed in as application arguments on launching the application.  Their port numbers are fixed at 46400 and 46410 respectively.

Example usage:

java -jar cau-client.jar 127.0.0.1:46400 127.0.0.1:46410 

The CAU client is bundled with the Fog CA public key which is used in the certificate path for the newly signed certificate.

