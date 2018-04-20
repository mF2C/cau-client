CAU client (version mF2c IT1 demo)

This application supports the agent registration process.  It is triggered by the Discovery block to obtain an agent certificate from the mF2C cloud CA via a TLS1.2 TCP-IP call to the regional CAU.  Then it validates the newly minted agent certificate with the leader agent via a TLS handshake and caches the leader certificate obtained during the handshake process. 

The socket server runs on 127.0.0.1:0.  The port will be assigned at deploy time by the system.
Both the CAU and leader CAU ip:port are expected to be passed in as application arguments on launching the application.

Example usage:

java -jar cau.client.jar 127.0.0.1:46050 127.0.0.1:46051 

