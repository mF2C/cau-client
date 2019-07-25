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
package eu.mf2c.security.cc.cimi;


import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.SSLContext;

import org.apache.http.Header;
import org.apache.http.HttpHeaders;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHeader;
import org.apache.http.ssl.TrustStrategy;
import org.apache.http.util.EntityUtils;
import org.apache.log4j.Logger;

import eu.mf2c.security.cc.StoreManagerSingleton;
import eu.mf2c.security.util.JsonUtils;
import eu.mf2c.security.util.Properties;

/**
 * Rest client to interact with the local mF2C CIMI instance. CIMI is the single
 * interface to an mF2C agent and it controls access to the agent resources
 * under its control. CIMI only accepts calls from clients who are registered as
 * an internal user. To enable inter&#45;agent communication, Cau&#45;Client
 * provides a method for registering other Agents with the local CIMI.
 * <p> * 
 * @author Shirley Crompton
 * email shirley.crompton@stfc.ac.uk
 * org Data Science and Technology Group, UKRI Science and Technology Council
 * Created 30 May 2019
 */
public class CimiClient {
	// use this client to register cimi user (leader/child)
	/*
	 * Basic curl commands: curl -XPOST "${BASE_API_URL}/user-profile" -ksS -H
	 * 'slipstream-authn-info: internal ADMIN' -H 'content-type: application/json' -
	 * create user example curl -XPOST "${BASE_API_URL}/user" -ksS -H 'content-type:
	 * application/json' -d '{ "userTemplate": { "href":
	 * "user-template/self-registration", "password": "testpassword",
	 * "passwordRepeat" : "testpassword", "emailAddress": "testuser@testemail.com",
	 * "username": "'$USER'" }
	 * 
	 * only relevant for full normal agent: we add the leader user after getting the
	 * X509 cert for Leader agent Leader's discovery module handle registering child
	 * agents in the leader's CIMI instance
	 */
	/** Message Logger attribute */
	protected static Logger LOGGER = Logger.getLogger(CimiClient.class);

	/**
	 * Default constructor
	 */
	public CimiClient() {
	}
	/**
	 * Register the CIMI user using a post operation
	 * <p>
	 * @param user	the {@link CimiUserTemplate <em>CimiUserTemplate</em>} object
	 * @return	the HTTP status code for the post operation
	 */
	public int post(CimiUserTemplate user) {
		LOGGER.debug("Creating request json...");
		CloseableHttpResponse res = null;
		CloseableHttpClient httpClient = null;
		int rc = 0;
		try {
			String request = JsonUtils.getJsonStr(user);
			StringEntity str = new StringEntity(request);
			// Some custom method to create HTTP post object
			HttpPost post = new HttpPost(Properties.cimiUrl + Properties.USER); // "https://localhost/api/user"			
			post.addHeader("Content-type", "application/json"); //need http-cache lib 
			post.setEntity(str);
			// Get http client which is configured to trust all cert and do not check
			// hostname
			httpClient = getCloseableHttpClient();
			LOGGER.debug("About to executive post ...");
			// Execute HTTP method
			res = httpClient.execute(post);
			LOGGER.debug("About to verify response ....");
			// Verify response
			rc = res.getStatusLine().getStatusCode();
			if (rc == 200 || rc == 201) {
				String json = EntityUtils.toString(res.getEntity());
				LOGGER.debug("CIMI Response json : " + json);
			} else {
				LOGGER.debug("CIMI error/warning when regisering CIMI user : " + res.getStatusLine().getReasonPhrase());
			}
	
		} catch (Exception e) {
			LOGGER.debug("Error trying to register CIMI user(" + user.getUser().getName() + ") :" + e.getMessage());
		} finally {
			if (res != null) {
				try {
					res.close();
				} catch (IOException e) {
					// just log it
					LOGGER.debug("Error encountered trying to close the CIMI http response object....");
				}
			}
			if (httpClient != null) {
				try {
					httpClient.close();
				} catch (IOException e) {
					// just log it
					LOGGER.debug("Error encountered trying to close the CIMI http client object....");
				}
			}
		}
		return rc;
	}

	/**
	 * Configure an HTTP Client for the post operation. As the CIMI target exists in
	 * the local private network, the client bypasses hostname and certificate trust
	 * path validation.
	 * <p>
	 * 
	 * @return the {@link org.apache.http.impl.client.CloseableHttpClient
	 *         <em>CloseableHttpClient</em>} object
	 * @throws Exception
	 *             configuration exception
	 */
	public CloseableHttpClient getCloseableHttpClient() throws Exception {
		LOGGER.debug("about to create closeable http client ...");
		CloseableHttpClient httpClient = null;
		try {

			KeyStore keystore = StoreManagerSingleton.getInstance().getKeyStore();
			SSLContext sslContext = org.apache.http.ssl.SSLContexts.custom()
					.loadTrustMaterial(null, new TrustStrategy() {
						// trust all, we are in the local private network
						public boolean isTrusted(X509Certificate[] arg0, String arg1) throws CertificateException { 
							return true;
						}
					}).setKeyStoreType("JKS").loadKeyMaterial(keystore, "stfc-mf2c-jkspass".toCharArray()).build();
			LOGGER.debug("about to build http client ...");
			//turn off hostname verification
			httpClient = HttpClients.custom().setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE). 
					setSSLContext(sslContext). // set context and trust all cert
					setDefaultHeaders(getHeadersAsList()). // set headers
					build();
		} catch (Exception e) {
			String msg = "Error posting user to CIMI : " + e.getMessage();
			throw new Exception(msg);
		}
		return httpClient;
	}

	//////////////////////////////// private methods////////////////////////////////
	/**
	 * Set up headers for the CIMI post action
	 * <p>
	 * 
	 * @return
	 */
	private List<Header> getHeadersAsList() {

		final List<Header> headers = new ArrayList<Header>();
		headers.add(new BasicHeader(HttpHeaders.CONTENT_TYPE, "application/json"));
		headers.add(new BasicHeader("slipstream-authn-info", "super ADMIN"));
		return headers;
	}
}
