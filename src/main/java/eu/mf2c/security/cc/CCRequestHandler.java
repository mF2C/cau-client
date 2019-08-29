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
package eu.mf2c.security.cc;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.apache.log4j.Logger;

import eu.mf2c.security.Exception.CauClientException;
import eu.mf2c.security.util.JsonUtils;
import eu.mf2c.security.util.Properties;
import eu.mf2c.security.util.Utils;
import eu.mf2c.security.cc.cau.CauClient;
import eu.mf2c.security.cc.cimi.*;

/**
 * A threaded handler to handle calls to the {@link CauClientServer <em>BasicSocketServer</em>}
 * <p>
 * @author Shirley Crompton
 * email  shirley.crompton@stfc.ac.uk
 * org Data Science and Technology Group,
 *      UKRI Science and Technology Council
 * Created 29 May 2019
 */
public class CCRequestHandler extends Thread {
	/** Message logger attribute */
	protected static Logger LOGGER = Logger.getLogger(CCRequestHandler.class);
	/** Client socket attribute */
	public Socket sock;
	/** request parameters */
	private Map<String, String> params = null;
	/** request operation flag */
	private int op = 0; //1=getpubkey, 2=adduser, 3=getCSR //23July19 adduser obsolete
	/**
	 * Constructor
	 * <p>
	 * @param s
	 *            The client connection object
	 */
	public CCRequestHandler(Socket s) {
		this.sock = s;
	}
	/**
	 * Run method for this handler thread. It processes the incoming message, gets
	 * the correct type of token created and sends it back to the client.
	 * <p>
	 * There are three different types of requests&#58;
	 * <ul>
	 * <li>get a new Agent certificate</li>
	 * <li>get an Agent Public Key identified by a device id.</li>
	 * <li>register an internal user on the local CIMI instance.</li>
	 * </ul>
	 * <p>
	 * If there are exceptions, an error code is returned&#58;
	 * <ul>
	 * <li>err1 &#58; get certificate error</li>
	 * <li>err2 &#58; get public key error</li>
	 * <li>err3 &#58; register CIMI user errors</li>
	 * <li>err4 &#58; other processing errors</li>
	 * </ul>
	 */
	@Override
	public void run() {
		BufferedReader inReader = null;
		//BufferedInputStream in = null;
		OutputStream os = null;
		try {
			os = sock.getOutputStream();
			LOGGER.debug("Connection received from " + sock.getInetAddress().getHostName() + " : " + sock.getPort());
			// set up input read
			//
			LOGGER.debug("Before reading in message ....");
			inReader = new BufferedReader(new InputStreamReader(sock.getInputStream(), StandardCharsets.UTF_8));
			String message = inReader.readLine(); // should be an UTF8 String
			//
			String resp = null;
			if (message != null && !message.isEmpty()){
				LOGGER.debug("Incoming message: " + message);
				//
				try {
					resp = this.handleRequest(message);
					if (resp == null || resp.isEmpty()) {
						throw new Exception("Request message is null/empty!");
					}
				} catch (Exception e) {
					String msg = e.getMessage();
					//show the full msg now
					LOGGER.error("Error handling request : " + msg);
					//
					String errCode = "err4"; //default to other errors
					//err3 is obsolete as we don't register CIMI user
					if (msg.startsWith("Error registering CIMI user")) {
						errCode = "err3";
					} else if (msg.startsWith("Error getting public key")) {
						errCode = "err2";
					} else if(msg.startsWith("Error getting X509 cert")){ 
						errCode = "err1";
					}
					os.write(errCode.getBytes(StandardCharsets.UTF_8));
					os.flush();
					return; //we returned an error code, stop now
				}//end inner catch exception
				//
				// ok, no exception and let's process the output/
				String response = resp + "\n"; //add new line to signal end of input
				byte[] msgBytes = null;
				if(op == 1) {
					msgBytes = response.getBytes(); //it a PEM we are returning, no need to UTF8 it
				}else {
					msgBytes = response.getBytes(StandardCharsets.UTF_8);
				} 
				LOGGER.debug("about to stream response (" + resp.length() + "bytes) to client....");
				//
				os.write(msgBytes);
				os.flush();
			}//end if msg is null....
		} catch (Exception e) {
			//error to do with reading in request
			LOGGER.debug("CCReqHandler encountered exception " + e.getMessage());
			if (os != null) {
				try {
					String msg = "err4: " + e.getMessage();
					os.write(msg.getBytes(StandardCharsets.UTF_8));
					os.flush();
				} catch (IOException e1) {
					LOGGER.error("Error trying to close output stream: " + e1.getMessage());
				}
			}
		} finally {			
			try {
				if(os != null) {
					os.close();
				}
				if(inReader != null) {
					inReader.close();
				}
				LOGGER.debug("CCRequest handler closing client connection ....");
				if (this.sock.isConnected()) {
					this.sock.close();
				}
			} catch (IOException e) {
				LOGGER.error("Error trying to close client connection and release resources!");
			}
		}
	}
	/**
	 * Handle the request.  Returns OK for the register CIMI user and get Agent
	 * certificate methods.  Returns an RSA public key in PEM format for the 
	 * get public key method.
	 * <p>
	 * @param message	the request message {@link java.lang.String <em>String</em>} object
	 * @return			the response {@link java.lang.String <em>String</em>} object 			
	 * @throws CauClientException	on errors
	 */
	public String handleRequest(String message) throws CauClientException{
		// here I assume that the caller has guarded for empty or null !!!!!!
		String result = "OK";
		// handle the request
		this.params = Utils.getValues(message);
		if(this.params.isEmpty()) {  //Utils instantiates the Map
			throw new CauClientException("Failed to extract parameters from request message!  Cannot proceed!");
		}
		//two type of requests
		if(this.params.containsKey("getpubkey")) {		
			op = 1;
			result = this.getPubKey(this.params.get("getpubkey"));					
		}else if(this.params.containsKey("deviceID")) {		
			op = 3;
			//IDkey=someIDKey,(leaderIP=http://..., NOT REQUIRED)detectedLeaderID=leaderDeviceID,deviceID=AgentDeviceID
			//idkey : (leaderip : NOT REQUIRED)	leaderid  : deviceid 
			LOGGER.debug("request handler about to call register Agent.....");
			this.registerAgent();
		}else {
			LOGGER.error("Unknown requests!");
		}
		return result;
	}	
	
	////////////////////////////////////private methods to handle the request////////////
	
	/**
	 * This handles the IT2 call to register an Agent.  The process procures an mF2C Agent
	 * certificate from the cloud CA using a local CAU service.
	 * <p>
	 * @throws CauClientException	on error
	 */
	private void registerAgent() throws CauClientException {
		/*The CAU-client creates the CSR and then call the CAU to get CA to sign CSR.  
		 * On CAU returns, the CAU client gets 
		 * AgentSingleton to store credentials than writes the credentials to pkidata*/
		try {	
			//System.out.println("about to instantiate CauClient....");
			CauClient client = new CauClient(this.params);
			client.getCert(); //if it fails, you get an exception
			
			//register leader in the local CIMI db, AgentSingleton should have stored the credentials to the keystore by now
			/* 19 June 2019 SixQ did not impl user matching when generating the session token
			 * if(Properties.agentType.equals("full")) {
				this.registerUser(this.params.get("detectedLeaderID"));		
			}*/
		}catch(Exception e) {
			throw new CauClientException("Error getting X509 cert : " + e);
		}
	}
	
	
	/**
	 * Handles request to retrieve a public key.
	 * <p>
	 * @param deviceID	a {@link java.lang.String <em>String</em>} representation
	 * 		of the Agent&#39;s deviceID
	 * @return a {@link java.lang.String <em>String</em>} representation of the RSA public key 
	 * 		in PEM format
	 * @throws CauClientException 	if operation fails
	 * 
	 */
	private String getPubKey(String deviceID) throws CauClientException {
		//we return a PEM string here, ac-lib converts the PEM to JWK
		CauClient ccClient = new CauClient();
		return ccClient.getPublicKey(deviceID);
	}
	/**
	 * Handles request to register a CIMI user.
	 * <p>
	 * @param deviceID	a {@link java.lang.String <em>String</em>} representation
	 * 		of the Agent&#39;s deviceID
	 * @throws CauClientException 	if the post operation fails
	 * 
	 */
	@SuppressWarnings("unused")
	private void registerUser(String deviceID) throws CauClientException {
		//:TODO needs to swap template with the one to be provided by SixQ
		CimiUserTemplate.CimiUser user = new CimiUserTemplate.CimiUser();
		user.setHref("user-template/self-registration");
		user.setEmailAddress("AnotherDummy@any.org.co.uk");
		user.setName(deviceID);
		user.setPassword("abcde12345");
		user.setPasswordRepeat(user.getPassword());
		//
		CimiUserTemplate userwrapper = new CimiUserTemplate(user);
		//
		CimiClient client = new CimiClient();
		try {
			LOGGER.debug("About to call CimiClient.postUser with user details: \n" + JsonUtils.getJsonStr(userwrapper));			
			int rc = client.post(userwrapper); //use just httpclient, this works....
			if(rc != 200 &&  rc!= 201) { //CIMI normally sends 201
				throw new Exception("CIMI RC(" + String.valueOf(rc) + ")");
			}//no need to do anything if user is created
		} catch (Exception e) {
			String msg = "Error registering CIMI user : " + e.getMessage();
			throw new CauClientException("Error getting public key : " + msg);
		}
	}
}
