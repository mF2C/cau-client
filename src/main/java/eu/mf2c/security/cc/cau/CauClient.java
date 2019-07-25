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
package eu.mf2c.security.cc.cau;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

import org.apache.http.Header;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHeader;
import org.apache.http.util.EntityUtils;
import org.apache.log4j.Logger;

import eu.mf2c.security.Exception.CauClientException;
import eu.mf2c.security.Exception.StoreManagerSingletonException;
import eu.mf2c.security.cc.StoreManagerSingleton;
import eu.mf2c.security.util.Properties;

/**
 * A socket client to communicate with the regional CAU and obtain an agent
 * certificate. In IT&#45;1&#58; after obtaining the certificate from the fog CA
 * via the regional CAU, it will perform a SSL handshake with the leader CAU to
 * verify the certificate.
 * <p>
 * 
 * @author Shirley Crompton, 
 * email shirley.crompton@stfc.ac.uk 
 * org 	Data Science and Technology Group
 * 		UKRI Science and Technology Council 
 * created 5 Apr 2018
 *
 */
public class CauClient {
	// 9May2019 changed to a synchronous call
	// we need to change this to an HTTP client as the CAU will be a Springboot
	// application running with an embedded server
	// we need 2 methods:
	// 1) getPublicKey(deviceID) 2) getCert(csr.....) IT1 method
	protected Logger LOGGER = Logger.getLogger(CauClient.class);
	/** ssl context attribute */
	private SSLContext sslContext = null;
	/**
	 * ssl socket factory attribute private SSLSocketFactory sslFactory = null;
	 */
	/** ssl socket object */
	private SSLSocket socket = null;
	/**
	 * The next four attributes are passed in as main arguments (June19 these are
	 * stored in Properties)
	 */
	/**
	 * CAU IP attribute/ private InetAddress cauIP = null; /** CAU port attribute
	 * private int cauPort = 46400; //default for IT1 /** leader CAU IP attribute
	 * private InetAddress leaderCauIP = null; /** leader CAU port attribute private
	 * int leaderCauPort = 46401; //default for IT1
	 */
	/** the next four attributes are passed in by the discovery block */
	/** lead agent device ID attribute */
	private String leaderID = null;
	/**
	 * lead agent IP address attribute / private String leaderIP = null;* /** user
	 * ID key
	 */
	private String idKey = null;
	/** agent device ID */
	private String deviceID = null;
	/** certificate signing request */
	private String csr = null;
	/** request String to CAU */
	private String request = null;
	/** operation */
	private int op; // 1 = getPK; 2 = registerUser
	/** Client to interact with CAU */
	private CloseableHttpClient client;

	/**
	 * StoreManagerSingle instance protected StoreManagerSingleton sms =
	 * StoreManagerSingleton.getInstance();
	 */

	/** properties cache */
	// private HashMap<String, String> cache = null;

	/**
	 * Create an SSLContext object with a truststore. The regional CAU should not
	 * require client authentication.
	 * <p>
	 * 
	 * @return the created SSLContext object
	 * @throws Exception
	 *             on error
	 * 
	 *             private SSLContext createSSLContext() throws Exception {
	 *             //Security.addProvider(new BouncyCastleProvider()); // set up a
	 *             key manager for our local credentials TrustManagerFactory
	 *             trustManagerFactory = TrustManagerFactory.getInstance(
	 *             TrustManagerFactory.getDefaultAlgorithm());
	 *             trustManagerFactory.init(StoreManagerSingleton.getInstance().getTrustStore());
	 *             //we are doing one way authentication - authenticating server
	 *             certificate // // create a context and set up a socket factory
	 *             SSLContext sslContext = SSLContext.getInstance("TLS"); //1.2
	 *             default sslContext.init(null,
	 *             trustManagerFactory.getTrustManagers(), null); //just 1 way
	 * 
	 *             return sslContext; }
	 */
	/**
	 * Default do nothing constructor
	 */
	public CauClient() {

	}

	/**
	 * Call the CAU to retrieve the public key associated with the provided Agent
	 * identifier.
	 * <p>
	 * 
	 * @param targetDID
	 *            a {@link java.lang.String <em>String</em>} representation of the
	 *            unique Agent identifier
	 * @return the retrieved public key in PEM formet
	 * @throws CauClientException
	 *             on processing error
	 */
	public String getPublicKey(String targetDID) throws CauClientException {
		this.op = 1;
		// get a PEM format of device id
		String pem = "";
		CloseableHttpResponse response1 = null;
		// https://<ip:port>/cau/publickey?deviceId=<deviceID>
		HttpGet httpGet = new HttpGet("https://" + Properties.cauIP +  Properties.cauContext + Properties.PK + "?deviceid=" + targetDID);
		try {
			this.getCloseableHttpClient();
			response1 = client.execute(httpGet);
			LOGGER.debug(response1.getStatusLine().getReasonPhrase());
			int status = response1.getStatusLine().getStatusCode();
			if (status >= 200 && status < 300) {
				//should be a small object
				pem = EntityUtils.toString(response1.getEntity());
			}else {
				throw new Exception("CAU returned error code: " + status);
			}
		} catch (Exception e) {
			//
			throw new CauClientException(e);
		} finally {
			if (response1 != null) {
				try {
					response1.close();
				} catch (IOException e) {
					LOGGER.warn("Error closing response object : " + e.getMessage());
				}
			}
			if (this.client != null) {
				try {
					this.client.close();
				} catch (IOException e) {
					LOGGER.warn("Error closing client object : " + e.getMessage());
				}
			}
		}
		return pem;
	}
	////////////////////////////////////////////////////////// old code

	/**
	 * Construct an instance to handle CSR request.
	 * <p>
	 * 
	 * @param params
	 *            A {@link java.util.Map <em>Map</em>} containing the CAU and leader
	 *            CAU connection properties.
	 * @throws IllegalArgumentException
	 *             If incorrect parameters received
	 */
	public CauClient(Map<String, String> params) throws IllegalArgumentException {
		// we need to escalate exceptions to the parent, do these now before starting
		// the thread
		// extract the connection params now
		/*
		 * these are now stored in Properties this.cauIP =
		 * Utils.getInetAddress(Properties.cauIP); if(Properties.cauIP.contains(":")) {
		 * this.cauPort = Utils.getPortNum(Properties.cauIP); } this.leaderCauIP =
		 * Utils.getInetAddress(Properties.leaderCauIP);
		 * if(Properties.leaderCauIP.contains(":")) { this.leaderCauPort =
		 * Utils.getPortNum(Properties.leaderCauIP); }
		 */
		this.idKey = params.get("IDkey");
		// this.leaderIP = params.get("leaderIP");
		this.deviceID = params.get("deviceID");
		this.leaderID = params.get("detectedLeaderID"); // if agent is leader leaderID=deviceID
		// this.createSSLContext();
		LOGGER.debug("Got IDkey: " + this.idKey + /* ", leaderIP: " + this.leaderIP + */", deviceID: " + this.deviceID
				+ ", leaderID: ");
	}

	/**
	 * Run the process to establish a secure TLS connection with the regional CAU.
	 * Then send a request message for an agent certificate. The certificate is
	 * written to a shared file volume within the container host.
	 * <p> 
	 * @throws CauClientException
	 *             on error
	 */
	public void getCert() throws CauClientException {
		LOGGER.debug("CAU-client getCert method called.....");
		this.op = 3;
		CloseableHttpResponse res = null;
		String certString = "";
		try {
			// first get the CSR, CN = first 64 chars of the device id
			this.csr = StoreManagerSingleton.getInstance().createCSRString(this.deviceID.substring(0, 63));
			/*
			 * compiles the request String csr, agent deviceid, leader deviceid, leader ip,
			 * agent type
			 */
			this.getRequestMsg();
			// get the https client
			this.getCloseableHttpClient();
			// prepare the post
			HttpPost post = new HttpPost("https://" + Properties.cauIP + Properties.cauContext + Properties.CERT); // <host:port>/cau/cert
			post.setEntity(new StringEntity(this.request));
			LOGGER.debug("About to executive post ...");
			// Execute HTTP method
			res = this.client.execute(post);
			LOGGER.debug("About to verify response ....");
			// Verify response
			LOGGER.debug(res.getStatusLine().getReasonPhrase());
			int status = res.getStatusLine().getStatusCode();
			long length = res.getEntity().getContentLength();
			// System.out.println("RC " + status + " length: " + String.valueOf(length));
			LOGGER.debug("RC " + status + " length: " + String.valueOf(length));
			if (status >= 200 && status < 300) {
				// System.out.println("About to get content using EntityUtils...");
				LOGGER.debug("About to get content using EntityUtils...");
				if (length != -1 && length < 2048) {
					certString = EntityUtils.toString(res.getEntity());
					// System.out.println(cert);
				} else {
					// read in stream, but cert normally under 2k
					// System.out.println("About to get content as stream...");
					LOGGER.debug("About to get content as stream...");
					certString = getCertStr(res.getEntity().getContent());
				}
				/*
				 * BufferedReader br; br = new BufferedReader(new
				 * InputStreamReader(res.getEntity().getContent())); String line = ""; while
				 * ((line = br.readLine()) != null) { certString += line; }
				 */
				if (certString == null || certString.isEmpty()) {
					throw new CauClientException("Error posting for a certificate! null/empty response!");
				} else {
					LOGGER.debug("CAU returns : " + (certString != null ? certString : "NULL"));
				}
			} else {
				// LOGGER.error("Error posting user : " +
				// res.getStatusLine().getReasonPhrase());
				throw new Exception("Error posting csr : " + res.getStatusLine().getReasonPhrase());
			}
		} catch (Exception e) {
			throw new CauClientException(e);
		} finally {
			if (res != null) {
				try {
					res.close();
				} catch (IOException e) {
					LOGGER.warn("Error closing response object : " + e.getMessage());
				}
			}
			if (this.client != null) {
				try {
					this.client.close();
				} catch (IOException e) {
					LOGGER.warn("Error closing client object : " + e.getMessage());
				}
			}
		}
		// OK continues
		// generate the certificate
		X509Certificate agentCert;
		try {
			agentCert = StoreManagerSingleton.getInstance().generateCertFromBytes(certString.getBytes());
			// end 27/2/2019
			// validate certificate, just a simple check for the moment
			LOGGER.info("agent certificate dn: " + agentCert.getSubjectX500Principal().getName());
			LOGGER.info("agent cert issuer dn: " + agentCert.getIssuerDN().getName());
			// store to keystore (use deviceID as an alias)
			StoreManagerSingleton.getInstance().storeKeyEntry(this.deviceID, this.leaderID, agentCert);
			// 28Feb2019 store certificate to /pkiData/server.crt
			StoreManagerSingleton.getInstance().writeCertFile(agentCert);
			//
			StoreManagerSingleton.getInstance().writeDeviceID(this.deviceID); // added 30 April 2019
		} catch (StoreManagerSingletonException | KeyStoreException e) {
			// TODO Auto-generated catch block
			throw new CauClientException("Error creating/writing cert: " + e.getMessage());
		}
	}

	/**
	 * Read in the CA response as an inputstream object
	 * <p> 
	 * @param is
	 *            the response input stream
	 * @return a {@link java.lang.String <em>String</em>} representation of the X.509 certificate object
	 * @throws CauClientException
	 *             on error
	 * 
	 */
	public String getCertStr(InputStream is) throws CauClientException {
		String cert = "";
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		BufferedInputStream in = null;
		try {
			baos = new ByteArrayOutputStream();
			in = new BufferedInputStream(is);
			// Create buffer: typical cert is about 2KB, not sure about underlying
			// capability, use a small buffer
			byte[] buffer = new byte[1024]; //
			int bytesRead = 0;
			// log.debug("waiting for CA response....");
			while ((bytesRead = in.read(buffer, 0, 1024)) != -1) {
				//
				baos.write(buffer, 0, bytesRead); // keep adding to the buffer
				LOGGER.info("written " + bytesRead + " bytes");
			}
			baos.flush();
			cert = new String(baos.toByteArray(), StandardCharsets.UTF_8);
		} catch (Exception e) {
			throw new CauClientException(e);
		} finally {
			if (in != null) {
				try {
					in.close();
				} catch (IOException e) {
					LOGGER.warn("Error closing response stream : " + e.getMessage());
				}
			}
		}
		return cert;
	}

	/**
	 * Create an http client for interacting with the CAU rest server
	 * <p>
	 * 
	 * @throws {@link
	 *             CauClientException <em>CauClientException</em>} on error setting
	 *             up the client
	 */
	private void getCloseableHttpClient() throws CauClientException {
		LOGGER.debug("about to create closeable http client ...");
		try {
			SSLContext sslContext = org.apache.http.ssl.SSLContexts.custom()
					.loadTrustMaterial(StoreManagerSingleton.getInstance().getTrustStore(),
							new org.apache.http.conn.ssl.TrustSelfSignedStrategy())
					.setKeyStoreType("JKS").loadKeyMaterial(StoreManagerSingleton.getInstance().getKeyStore(),
							StoreManagerSingleton.getInstance().getStorePass().toCharArray())
					.build();
			LOGGER.debug("about to build http client ...");
			this.client = HttpClients.custom().setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE). // turn off
																										// hostname
																										// verification
					setSSLContext(sslContext). // set context and trust all cert
					setDefaultHeaders(getHeadersAsList()). // set headers
					build();
		} catch (Exception e) {
			throw new CauClientException(e);
		}
	}

	/**
	 * Set HTTP headers for the rest call to CIMI
	 * <p>
	 * 
	 * @return a list of HTTP headers
	 */
	private Collection<? extends Header> getHeadersAsList() {
		final List<Header> headers = new ArrayList<Header>();
		headers.add(new BasicHeader(org.apache.http.HttpHeaders.CONTENT_TYPE, "text/plain"));
		headers.add(new BasicHeader(org.apache.http.HttpHeaders.ACCEPT, "text/plain"));
		headers.add(new BasicHeader(org.apache.http.HttpHeaders.ACCEPT_CHARSET, "utf-8"));
		return headers;
	}

	/**
	 * Create the CAU request message
	 */
	private void getRequestMsg() {
		// csr=csrContentAsString,IDkey=someIDKey,MACaddr=ab:cd:ef:01:23:45,detectedLeaderID=56789,deviceID=123456789
		// 27June2019 changed = to :
		String l_deviceId = "deviceID:" + this.deviceID;
		String l_leaderId = "detectedLID:" + this.leaderID;
		// String l_leaderIP = "detectedLIP:" + this.leaderIP;
		String l_idKey = "IDKey:" + this.idKey;
		// String l_aType = "type:" + Properties.agentType;
		//
		// 9May2018 removed base64 encoding
		// return Base64.getEncoder().encode(("csr=" + csrString + "," + l_leaderId +
		// "," + l_leaderMacAddr + "," + l_idKey + "," + l_deviceId).getBytes());
		this.request = (/* l_aType + ", */"csr:" + this.csr + "," + l_leaderId + "," + /* l_leaderIP + "," + */l_idKey
				+ "," + l_deviceId);
		LOGGER.debug("The request msg: " + this.request);
	}

	/**
	 * Print properties of the client socket for debug purposes.
	 * 
	 * private void logSocketInfo() { LOGGER.debug(" Remote address = " +
	 * this.socket.getInetAddress().toString()); LOGGER.debug(" Remote port = " +
	 * this.socket.getPort()); LOGGER.debug(" Local socket address = " +
	 * this.socket.getLocalSocketAddress().toString()); LOGGER.debug(" Local address
	 * = " + this.socket.getLocalAddress().toString()); LOGGER.debug(" Local port =
	 * " + this.socket.getLocalPort()); LOGGER.debug(" Need client authentication =
	 * " + this.socket.getNeedClientAuth()); LOGGER.debug("SSL protocol used: " +
	 * sslContext.getProtocol()); LOGGER.debug("Enabled cipher suites: " +
	 * Arrays.toString(this.socket.getEnabledCipherSuites())); }
	 */

	/**
	 * Print properties of the active session for debug purposes.
	 * <p>
	 * 
	 * @param session
	 *            the current session object
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
	 * 
	 * @author Shirley Crompton, shirley.crompton@stfc.ac.uk org Data Science and
	 *         Technology Group, UKRI Science and Technology Council Date 13 Apr
	 *         2018
	 * 
	 *         class SimpleHandShakeCompletedListener implements
	 *         HandshakeCompletedListener{ //:TODO extract this out as an
	 *         independent class in next iteration or make it annonymous /** server
	 *         name attribute, the name will be used as the truststore alias private
	 *         String server = null; /** Constructor
	 *         <p>
	 * @param serverName
	 *            Name of the server involved in the handshaking process.
	 * 
	 *            public SimpleHandShakeCompletedListener(String serverName) {
	 *            this.server = serverName; }
	 * 
	 * @Override public void handshakeCompleted(HandshakeCompletedEvent event) { try
	 *           { //LOGGER.debug("\n Inside handshakecompleted listener...");
	 *           X509Certificate cert= (X509Certificate)
	 *           event.getPeerCertificates()[0]; String peer =
	 *           cert.getSubjectDN().getName(); LOGGER.debug("\n DN from " + server
	 *           + " : " + peer);
	 *           StoreManagerSingleton.getInstance().storeCertificate(server, cert);
	 *           } catch (SSLPeerUnverifiedException pue) { LOGGER.error(server + "
	 *           certificate unverified: " + pue.getMessage()); } catch
	 *           (StoreManagerSingletonException e) { // LOGGER.error("error storing
	 *           cau certificate: " + e.getMessage()); } }
	 * 
	 *           }
	 */

}
