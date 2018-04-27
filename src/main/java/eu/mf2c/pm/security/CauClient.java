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

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.apache.log4j.Logger;

import eu.mf2c.pm.security.Exception.CauClientException;
import eu.mf2c.pm.security.Exception.StoreManagerSingletonException;
import eu.mf2c.pm.security.util.Utils;

/**
 * A client to communicate with the local CAU and obtain an agent certificate.
 * In IT&#45;1&#58; after obtaining the certificate from the cloud CA via the local CAU, 
 * it will perform a SSL handshake with the leader CAU to verify the certificate.
 * Then it calls the Categorisation block via REST to trigger the agent categorisation
 * process.
 * <p>
 * @author Shirley Crompton, shirley.crompton@stfc.ac.uk
 * org Data Science and Technology Group,
 *     UKRI Science and Technology Council
 * Date 5 Apr 2018
 *
 */
public class CauClient extends Thread {
	
	protected Logger LOGGER = Logger.getLogger(CauClient.class);
	/** ssl context attribute */
	private SSLContext sslContext = null;
	/** ssl socket factory attribute */
	private SSLSocketFactory sslFactory = null;
	/** ssl socket object */
	private SSLSocket socket = null;
	/** The next four attributes are passed in as main arguments */
	/** CAU IP attribute*/
	private InetAddress cauIP = null;
	/** CAU port attribute */
	private int cauPort = 46400; //default for IT1
	/** leader CAU IP attribute*/
	private InetAddress leaderCauIP = null;
	/** leader CAU port attribute */
	private int leaderCauPort = 46401; //default for IT1
	/** the next four attributes are passed in by the discovery block */
	/** lead agent ID attribute */
	private String leaderID = null;
	/** lead agent MAC address attribute */	
	private String leaderMacAddr = null;
	/** agent ID key */
	private String idKey = null;
	/** agent device ID */
	private String deviceID = null;
	/** StoreManagerSingle instance */
	protected StoreManagerSingleton sms = StoreManagerSingleton.getInstance();
	
	/** properties cache */
	//private HashMap<String, String> cache = null;
	
	/**
	 * Create an SSLContext object with a truststore.
	 * The regional CAU should not require client authentifcation.
	 * <p>
	 * @return	the created SSLContext object
	 * @throws Exception	on error
	 */
	private SSLContext createSSLContext() throws Exception 
	    {
			//Security.addProvider(new BouncyCastleProvider());		
			// set up a key manager for our local credentials
			 TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
	                    TrustManagerFactory.getDefaultAlgorithm());
	         trustManagerFactory.init(sms.getTrustStore());
	         //we are doing one way authentication - authenticating server certificate
	         //			
			// create a context and set up a socket factory
			SSLContext sslContext = SSLContext.getInstance("TLS"); //1.2 default
			sslContext.init(null, trustManagerFactory.getTrustManagers(), null); //just 1 way 			

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
		this.idKey = cache.get("idKey");
		this.leaderMacAddr = cache.get("leaderMacAddr");
		this.deviceID = cache.get("deviceID");
		this.leaderID = cache.get("leaderID");
		//this.createSSLContext();
		
	}
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void run() {
		OutputStream out = null;
		BufferedInputStream in = null;
		//
		try {
			//create the socket now
			this.sslContext = createSSLContext();
			this.sslFactory = this.sslContext.getSocketFactory();
			//we block for comm with cau, so no time out
			this.socket = (SSLSocket) this.sslFactory.createSocket(this.cauIP, this.cauPort);
			LOGGER.debug("Created cau client socket for CAU(" + this.cauIP + ":" + this.cauPort + ")");
			//for debugging, can be disabled
			//this.logSocketInfo();
			//add listener to capture server certificate
			this.socket.addHandshakeCompletedListener(new SimpleHandShakeCompletedListener("cau"));
			this.socket.startHandshake(); 
			//should be OK to message now
			String csrString = null; 
			csrString = sms.createCSRString(); //CN = idKey
			//CSR=,leaderID=;leaderMacAddr=;idKey=;deviceId=
			byte[] msgBytes = getMsgBytes(csrString);
			out = this.socket.getOutputStream();
			//
			out.write(msgBytes);			
			//wait for response, should be the signed certificate object
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			in = new BufferedInputStream(this.socket.getInputStream());
			// Create buffer: typical cert is about 2KB, not sure about underlying capability, use a small buffer
			byte[] buffer = new byte[1024]; //
			int bytesRead = 0;
			while ((bytesRead = in.read(buffer, 0, 1024)) != -1) {
				baos.write(buffer, 0, bytesRead); //keep adding to the buffer
			}
			baos.flush();
			this.socket.close();
			
			/********************
			 
			  :TODO Not sure if CAU is going to return a certificate chain or just the signed certificate
			
			*********************/
			//needs to base64 decode
			String certStr = new String(Base64.getDecoder().decode(baos.toByteArray()), StandardCharsets.UTF_8);
			//generate the certificate with the UTF8 String
			X509Certificate agentCert = sms.generateCertFromBytes(certStr.getBytes());
			//validate certificate, just a simple check for the moment
			LOGGER.info("agent certificate dn: " + agentCert.getSubjectX500Principal().getName());
			//store to keystore
			sms.storeKeyEntry(this.idKey, this.leaderID, agentCert);//using leaderId as the fogId for IT1 demo
			//now verify certificate with leader agent's cau (basically an TLS handshake)
			LeadAgentCauClient leaderClient = new LeadAgentCauClient(sms, this.idKey, this.leaderCauIP, this.leaderCauPort, this.deviceID); //may throw exceptions on instantiation
		    leaderClient.start();
			//control passes over the the leader client, it will trigger the categorisation if the handshake with
		    //the leader CAU is OK
			
		} catch (Exception e) {
			 String msg = "Error running cau socket client: " + e.getMessage();
			 LOGGER.error(msg);
			 Thread thread = Thread.currentThread();
             thread.getUncaughtExceptionHandler().uncaughtException(thread, new CauClientException(msg));
		} finally{
			try {
				in.close();
				out.close();
				
			} catch (IOException e) {
				// Too bad
				LOGGER.error("failed to release resources : " + e.getMessage());
			}
		}		
	} 
		
		
		
		
	
	/**
	 * Create the request message for the local CAU
	 * <p>
	 * @param csrString		A {@link java.lang.String <em>String</em>} representation of the CSR.
	 * @return	A byte array representation of the message.
	 */
	private byte[] getMsgBytes(String csrString) {
		//
		String l_deviceId = "deviceId=" + this.deviceID;
		String l_leaderId = "leaderId=" + this.leaderID;
		String l_leaderMacAddr = "leaderMacAddr=" + this.leaderMacAddr;
		String l_idKey = "idKey=" + this.idKey;
		//
		return Base64.getEncoder().encode(("csr=" + csrString + ";" + l_leaderId + ";" + l_leaderMacAddr + ";" + l_idKey + ";" + l_deviceId).getBytes());		
	}
	/**
	 * Print properties of the client socket for debug purposes.
	 */
	private void logSocketInfo() {
	     LOGGER.debug("   Remote address = " + this.socket.getInetAddress().toString());
	     LOGGER.debug("   Remote port = "+ this.socket.getPort());
	     LOGGER.debug("   Local socket address = " + this.socket.getLocalSocketAddress().toString());
	     LOGGER.debug("   Local address = " + this.socket.getLocalAddress().toString());
	     LOGGER.debug("   Local port = "+ this.socket.getLocalPort());
	     LOGGER.debug("   Need client authentication = " + this.socket.getNeedClientAuth());
	     LOGGER.debug("SSL protocol used: " + sslContext.getProtocol());
		 LOGGER.debug("Enabled cipher suites: " + Arrays.toString(this.socket.getEnabledCipherSuites()));
	}
	/**
	 * Print properties of the active session for debug purposes.
	 * <p>
	 * @param session the current session object
	 */
	private void logSesisonInfo(SSLSession session) {
		try {
			java.security.cert.Certificate[] cchain = session.getPeerCertificates();
		    LOGGER.debug("The Certificates used by peer");
		    for (int i = 0; i < cchain.length; i++) {
		      LOGGER.debug(((X509Certificate) cchain[i]).getSubjectDN());
		    }					
		} catch (SSLPeerUnverifiedException e) {
			LOGGER.error("Error retriving certificates from SSLSession object! : " + e.getMessage());
		}
		    LOGGER.debug("Peer host is " + session.getPeerHost());
		    LOGGER.debug("Cipher is " + session.getCipherSuite());
		    LOGGER.debug("Protocol is " + session.getProtocol());
		    LOGGER.debug("ID is " + new BigInteger(session.getId()));
		    LOGGER.debug("Session created in " + session.getCreationTime());
		    LOGGER.debug("Session accessed in " + session.getLastAccessedTime());
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
	class SimpleHandShakeCompletedListener implements HandshakeCompletedListener{
		//:TODO extract this out as an independent class in next iteration or make it annonymous
		/** server name attribute, the name will be used as the truststore alias */
		private String server = null;
		/**
		 * Constructor 
		 * <p>
		 * @param serverName 	Name of the server involved in the handshaking process.  
		 */
		public SimpleHandShakeCompletedListener(String serverName) {
			this.server = serverName;
		}

		@Override
		public void handshakeCompleted(HandshakeCompletedEvent event) {
			try {
				//LOGGER.debug("\n Inside handshakecompleted listener...");
				X509Certificate cert= (X509Certificate) event.getPeerCertificates()[0]; 
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
