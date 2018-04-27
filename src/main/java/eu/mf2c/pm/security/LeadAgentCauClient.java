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

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.security.cert.X509Certificate;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.apache.log4j.Logger;

import eu.mf2c.pm.security.Exception.CauClientException;
import eu.mf2c.pm.security.Exception.StoreManagerSingletonException;

/**
 * A socket client to communicate with the Lead Agent CAU. In IT1 demo, we
 * perform a SSL handshake with the component to verify the newly obtained agent
 * certificate.
 * <p>
 * 
 * @author Shirley Crompton, shirley.crompton@stfc.ac.uk
 * org Data Science and Technology Group,
 *     UKRI Science and Technology Council
 * Date 16 Apr 2018
 */
public class LeadAgentCauClient extends Thread {
	/** Message logger attribute */
	protected Logger LOGGER = Logger.getLogger(LeadAgentCauClient.class);
	/** ssl context attribute */
	private SSLContext sslContext = null;
	/** ssl socket factory attribute */
	private SSLSocketFactory sslFactory = null;
	/** ssl socket object */
	private SSLSocket socket = null;
	/** The next four attributes are passed in as main arguments */
	/**
	 * CAU IP attribute private InetAddress cauIP = null; /** CAU port attribute
	 * private int cauPort = 0;
	 */
	/** leader CAU IP attribute */
	private InetAddress leaderCauIP = null;
	/** leader CAU port attribute */
	private int leaderCauPort = 0;
	/** the next four attributes are passed in by the discovery block */
	/** lead agent ID attribute */
	private String leaderID = null;
	/**
	 * lead agent MAC address attribute private String leaderMacAddr = null;
	 */
	/** agent ID key, which is used as the keystore entry alias */
	private String idKey = null;
	/** agent device ID */
	private String deviceID = null;
	 
	/** StoreManagerSingle instance */
	protected StoreManagerSingleton sms;

	/**
	 * Instantiate an instance.
	 * <p>
	 * 
	 * @param storeManager
	 *            an instance of the StoreManagerSingleton
	 * @param alias
	 *            the keystore entry alias for the agent certificate
	 * @param ip
	 *            the leader CAU InetAddress
	 * @param port
	 *            the leader CAU port number
	 * @param deviceID	the agent&#39;s device id 	
	 * 			  
	 */
	public LeadAgentCauClient(StoreManagerSingleton storeManager, String alias, InetAddress ip, int port, String deviceID) {
		this.sms = storeManager;
		this.idKey = alias;
		this.leaderCauIP = ip;
		this.leaderCauPort = port;
		this.deviceID = deviceID;
		// this.createSSLContext();
	}

	/**
	 * Create an SSLContext object with a truststore and a keystore. The leader CAU
	 * expects client authentication/
	 * <p>
	 * 
	 * @return the created SSLContext object
	 * @throws Exception
	 *             on error
	 */
	private SSLContext createSSLContext() throws Exception {
		// Security.addProvider(new BouncyCastleProvider());
		// set up a key manager for our local credentials
		TrustManagerFactory trustManagerFactory = TrustManagerFactory
				.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		trustManagerFactory.init(sms.getTrustStore());
		KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		keyManagerFactory.init(sms.getKeyStore(), sms.getStorePass().toCharArray());
		// create a context and set up a socket factory
		SSLContext sslContext = SSLContext.getInstance("TLS"); // 1.2 default
		sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null); // 2 ways
																											// authentication

		return sslContext;
	}
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void run() {
		OutputStream out = null;
		//
		try {
			// create the socket now
			this.sslContext = createSSLContext();
			this.sslFactory = this.sslContext.getSocketFactory();
			// we block for comm with cau, so no time out
			this.socket = (SSLSocket) this.sslFactory.createSocket(this.leaderCauIP, this.leaderCauPort);			
			LOGGER.debug("Created leader  client socket for Leader CAU(" + this.leaderCauIP + ":" + this.leaderCauPort + ")");
			// add listener to capture server certificate
			this.socket.addHandshakeCompletedListener(new SimpleHandShakeCompletedListener1("leaderCau"));
			this.socket.startHandshake();
			// should be OK to quit now, the handshake should be complete
			out = this.socket.getOutputStream();
			//
			out.write("bye".getBytes());
			this.socket.close();
		} catch (Exception e) {
			String msg = "Error running leadAgentCau socket client: " + e.getMessage();
			LOGGER.error(msg);
			Thread thread = Thread.currentThread();
			thread.getUncaughtExceptionHandler().uncaughtException(thread, new CauClientException(msg)); //could have own exception class
		} finally {
			try {
				out.close();
			} catch (IOException e) {
				// Too bad
				LOGGER.error("failed to release resources : " + e.getMessage());
			}
		}
		/********19Apr18 UPC has changed the interaction, policy block now does this 
		// create rest client to trigger categorisation
		HttpURLClient httpClient = new HttpURLClient(this.deviceID, this.idKey); 
		httpClient.start();
		//control passing over the the httpClient which trigger the categorisation block which is the last required action
		 *************************************************************/
	}

	/**
	 * Listener to capture the server certificate and load this into the trust store
	 * managed by the {@link StoreManagerSingleton <em>StoreManagerSingleton</em>}.
	 * <p>
	 * @author Shirley Crompton, shirley.crompton@stfc.ac.uk
	 * org Data Science and Technology Group,
	 *     UKRI Science and Technology Council
	 * Date 13 Apr 2018
	 */
	class SimpleHandShakeCompletedListener1 implements HandshakeCompletedListener {
		// :TODO extract this out as an independent class in next iteration!!!!!
		/** server name attribute, the name will be used as the truststore alias */
		private String server = null;

		/**
		 * Constructor
		 * <p>
		 * 
		 * @param serverName
		 *            Name of the server involved in the handshaking process.
		 */
		public SimpleHandShakeCompletedListener1(String serverName) {
			this.server = serverName;
		}

		@Override
		public void handshakeCompleted(HandshakeCompletedEvent event) {
			try {
				// LOGGER.debug("\n Inside handshakecompleted listener...");
				X509Certificate cert = (X509Certificate) event.getPeerCertificates()[0];
				String peer = cert.getSubjectDN().getName();
				LOGGER.debug("\n DN from " + server + " : " + peer);
				sms.storeCertificate(server, cert);
			} catch (SSLPeerUnverifiedException pue) {
				LOGGER.error(server + " certificate unverified: " + pue.getMessage());
			} catch (StoreManagerSingletonException e) {
				//
				LOGGER.error("error storing cau certificate: " + e.getMessage());
			}
		}

	}
}
