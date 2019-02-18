CAU client (version mF2c IT1 demo)

This application supports the agent registration process.  It is triggered by the Policy block to obtain an agent certificate from the mF2C fog CA via a TLS1.2 TCP-IP call to the regional CAU.  Then it validates the newly minted agent certificate with the leader agent via a TLS handshake with the leader agent CAU and caches the public key returned from the process to secure future communication.

The CAU client is an internal block of an Agent and is deployed as part of the Agent.  It communicates with the other Agent blocks over the private Docker network.  It communicates with the CAU middleware external to the Agent via TCP. 

For the IT1 demo, the socket server runs on 0.0.0.0:46065.  Both the CAU and leader CAU ip:port are expected to be passed in as application arguments on launching the application.

For the IT2 demo, the agent's private key and X509 certificate are written to the shared file volume pkidata.  Traefik will pick up the credentials and use the certificate as its server credential.

Example usage:

java -jar cau-client.jar 127.0.0.1:46400 127.0.0.1:46410 

The CAU client is bundled with the Fog and Untrust CA certificates which are used as appropriate in the certificate path for the newly signed certificates.  For IT1, the Untrust CA is used to issue new agent certificates.

