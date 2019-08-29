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

import java.util.HashMap;

import org.apache.log4j.Logger;

import eu.mf2c.security.Exception.StoreManagerSingletonException;
import eu.mf2c.security.util.Properties;

/**
 * Entry point to the application.  This application supports the Agent
 * registration and token en&#47;de&#45;cryption processes
 * <p>
 * In IT&#45;2, it needs to be started with the following arguments&#58;
 * <ul>
 * <li>CauIP</li>
 * <li>LeaderCauIP</li>
 * </ul>
 * This application runs a basic TCP&#45;IP socket server
 * to listen to UTF8 encoded plain text request messages from other agent blocks.  
 * <p>
 * For the agent registration process, the Policy block sends a request 
 * message with these mandatory parameters as a comma&#45;separated String&#58;
 * <ul>
 * <li>detectedLeaderID&#61;leaderDeviceIDValue</li>
 * <li>deviceID&#61;agentDeviceIdValue</li>
 * </ul>
 * On receiving the trigger, the application generates a CSR which it sends to
 * a CAU via TLS to request an agent certificate from the cloud CA.  On receipt
 * of the signed certificate, the application writes the certificate and the
 * agent&#39;s deviceID to the local docker volume for sharing with other agent
 * blocks and returns an &#34;OK&#34; response message to the client.
 * <p>
 * For getting an Agent&#39;s public key to support the token en&#47;de&#45;cryption process,
 * a client sends the Agent&#39;s deviceID in a request message&#58;
 * <ul>
 * <li>getPubKey&#61;deviceIDValue</li>
 * </ul>
 * The application contacts a CAU to retrieve the public key.
 * <p>
 * @author Shirley Crompton, shirley.crompton@stfc.ac.uk
 * org Data Science and Technology Group,
 *     UKRI Science and Technology Council
 * Date 9 Apr 2018
 */
public class IdManager {
	//
	protected static Logger LOGGER = Logger.getLogger(IdManager.class);	
	
	/**
	 * Retrieve the required Cau IP address.
	 * <p>
	 * @param moduleName	the required CAU.  This must be either#58;
	 * <ul>
	 * <li><em>cauIP</em></li>
	 * <li><em>leaderCauIP</em></li>
	 * </ul>
	 * <p>
	 * @return a {@link java.lang.String <em>String</em>} representation of the module name.
	 * @throws StoreManagerSingletonException 
	 * @throws CauClientException	if no argument or an incorrect name is provided.
	 
	public String getIPAddr(String moduleName) throws PMCertManagerException {
		if(moduleName == null || moduleName.isEmpty()) {
			throw new PMCertManagerException("Must provide componentName!");			
		}
		if(moduleName != "cauIP" && moduleName != "leaderCauIP") {
			throw new PMCertManagerException("Unknown componentName: " + moduleName + ".  Must be cauIP or leaderCauIP!");
		}
		return this.addressesHM.get(moduleName);
	}*/
	
	/**
	 * Set up the keystore to hold the bundled certificates for use in SSL handshake.
	 * It also trigger the creation of an RSA keypair.
	 * <p>
	 * @throws StoreManagerSingletonException	on creating the keystore or on loading the certificate PEMs.
	 */
	public void setupStoreManager() throws StoreManagerSingletonException {
		//a keystore is required for the TLS handshake
		
		//this creates the keystore, and loads the fog-sub, 01subca and 00root certificate PEMs.
		StoreManagerSingleton sms = StoreManagerSingleton.getInstance(); 
		//	
		sms.generateKeyPair();	
		//	18Feb19 save private key as /pki-data/server.key
		sms.writeKeyFile();
	}
	
	/**
	 * Entry point to the application.  
	 * Usage: CauClient &#60;CauIP&#91;#58;port number&#93;&#62; &#60;LeaderCauIP&#91;#58;port number&#93;&#62;
	 * <p>
	 * @param args	Application arguments.
	 * @throws Exception 	on error
	 */
	public static void main(String[] args) throws Exception {
		//
		if (args.length < 2) {
			throw new RuntimeException("Usage: CauClient <CloudCauIP:port number> <CauIP:port number>" /*<AgentType:full/micro>"*/);
		}
		if(args[0].isEmpty() || args[1].isEmpty() /* || args[2].isEmpty()*/) {
			throw new RuntimeException("Usage: CauClient <CloudCauIP:port number> <CauIP:port number>" /* <AgentType:full/micro>"*/);
		}
		IdManager pmCM = new IdManager(); //instantiate class
		//cache the values now
		//HashMap<String, String> addressesHM = new HashMap<String, String>();
		Properties.cauIP = args[0];
		Properties.cloudCauIP = args[1];
		//Properties.agentType = args[2];
		LOGGER.debug("Incoming arguments: " + Properties.cauIP + ", " + Properties.cloudCauIP);
		//bootstrap the storeManager now
		pmCM.setupStoreManager();
		//start the server to listen to triggers. 
		CauClientServer bss = new CauClientServer();
		//runs the server which is not threaded.  The control passes to the server.
		bss.runSocket();		
		//
		System.exit(0); 
		
	}

}
