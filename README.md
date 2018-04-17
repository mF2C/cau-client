CAU client (version mF2c IT1 demo)

This application supports the agent registration process.  It is triggered by the Discovery block to obtain an agent certificate from the mF2C cloud CA via a TLS1.2 TCP-IP call to the regional CAU.  Then it validates the newly minted agent certificate with the leader agent via a TLS handshake and caches the leader certificate obtained during the handshake process.  As the last step, the application makes a ReST call to the local Categorisation block to trigger the agent categorisation process.

