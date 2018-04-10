/**
 Copyright 2018 UKRI Science and Technology Facilities Council

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License 
 */
package eu.mf2c.pm.security;

import java.io.FileInputStream;
import java.net.InetAddress;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.util.HashMap;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import eu.mf2c.pm.security.util.Utils;

/**
 * A client to communicate with the local CAU and obtain an agent certificate.
 * In IT&#45;1&#58; after obtaining the certificate from the cloud CA via the local CAU, 
 * it will perform a SSL handshake with the leader CAU to verify the certificate.
 * Then it calls the Categorisation block via REST to trigger the agent categorisation
 * process.
 * <p>
 * @author Shirley Crompton
 * @email  shirley.crompton@stfc.ac.uk
 * @org Data Science and Technology Group,
 *      UKRI Science and Technology Council
 * @Created 5 Apr 2018
 *
 */
public class CauClient extends Thread {
	/** ssl context attribute */
	private SSLContext sslContext = null;
	/** ssl socket factory attribute */
	private SSLSocketFactory sslFactory = null;
	/** ssl socket object */
	private SSLSocket socket = null;
	/** CAU IP attribute*/
	private InetAddress cauIP = null;
	/** CAU port attribute */
	private int cauPort = 0;
	/** leader CAU IP attribute*/
	private InetAddress leaderCauIP = null;
	/** leader CAU port attribute */
	private int leaderCauPort = 0;
	
	
	
	/** properties cache */
	//private HashMap<String, String> cache = null;
	
	
	static SSLContext createSSLContext() throws Exception 
	    {
	        // set up a key manager for our local credentials
			KeyManagerFactory mgrFact = KeyManagerFactory.getInstance("SunX509");
			KeyStore clientStore = KeyStore.getInstance("PKCS12");

			clientStore.load(new FileInputStream("client.p12"), Utils.CLIENT_PASSWORD.toCharArray());

			mgrFact.init(clientStore, Utils.CLIENT_PASSWORD.toCharArray());
			
			// set up a trust manager so we can recognize the server
			TrustManagerFactory trustFact = TrustManagerFactory.getInstance("SunX509");
			KeyStore            trustStore = KeyStore.getInstance("JKS");
			
			trustStore.load(new FileInputStream("trustStore.jks"), Utils.TRUST_STORE_PASSWORD.toCharArray());
			
			trustFact.init(trustStore);
			
			// create a context and set up a socket factory
			SSLContext sslContext = SSLContext.getInstance("TLS");

			sslContext.init(mgrFact.getKeyManagers(), trustFact.getTrustManagers(), null);

			return sslContext;
	    }
	/**
	 * Construct an instance.
	 * <p>
	 * @param cache			A {@link java.util.HashMap <em>HashMap</em>} containing the CAU and 
	 * 						leader CAU connection properties.
	 * @throws Exception	On processing errors
	 */
	public CauClient(HashMap<String, String> cache) throws Exception  {
		//we need to escalate exceptions to the parent, do these now before starting the thread
		//extract the connection params now
		this.cauIP = Utils.getInetAddress(cache.get("cauIP"));
		if(cache.get("cauIP").contains(":")) {
			this.cauPort = Utils.getPortNum(cache.get("cauIP"));
		}
		this.leaderCauIP = Utils.getInetAddress(cache.get("leaderCauIP"));
		if(cache.get("leaderCauIP").contains(":")) {
			this.leaderCauPort = Utils.getPortNum(cache.get("leaderCauIP"));
		}
		//create the socket now
		this.sslContext = createSSLContext();
		this.sslFactory = this.sslContext.getSocketFactory();
		this.socket = (SSLSocket) this.sslFactory.createSocket(this.cauIP, this.cauPort);
	}

	@Override
	public void run() {
		//
		//load PEM files
		//establish TLS connection, validate server cert returned using intermediate and CA certs
		//generate RSA keypair and CSR
		//send CSR, block until cert is returned
		//validate the returned cert using fogCA and CA certs
		//handshake with leader CAU, cache the leader's server cert
		//create rest client to trigger categorisation
		
		
		
		
		
	}

	    

}
