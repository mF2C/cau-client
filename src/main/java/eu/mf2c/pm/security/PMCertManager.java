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

import java.util.HashMap;

import org.apache.log4j.Logger;

import eu.mf2c.pm.security.Exception.StoreManagerSingletonException;

/**
 * Entry point to the application.  This application supports the Agent
 * registration process.
 * <p>
 * In IT&#45;1, it needs to be started with the following arguments&#58;
 * <ul>
 * <li>CauIP</li>
 * <li>LeaderCauIP</li>
 * </ul>
 * This application runs a basic TCP&#45;IP socket server
 * to listen to the trigger from the Discovery block.  The latter will provide 
 * the following mandatory parameters in a &#59;&#45;separated String&#58;
 * <ul>
 * <li>leaderID&#61;&#60;ExampleString&#62;</li>
 * <li>LeaderMacAddr&#61;&#60;ExampleString&#62;</li>
 * <li>idKey&#61;&#60;ExampleString&#62;</li>
 * <li>deviceId&#61;&#60;ExampleString&#62;</li>
 * </ul>
 * On receiving the trigger, the application will connect via TLS to the local
 * CAU to request an agent certificate signed by the cloud CA.
 * Then it performs a handshake with the leader agent to validate the new certificate.
 * After which, it contacts the Categorisation block via ReST to initiate the agent 
 * categorisation process.
 * <p>
 * @author Shirley Crompton, shirley.crompton@stfc.ac.uk
 * org Data Science and Technology Group,
 *     UKRI Science and Technology Council
 * Date 9 Apr 2018
 */
public class PMCertManager {
	//
	protected static Logger LOGGER = Logger.getLogger(PMCertManager.class);	
	
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
	 * @throws PMCertManagerException	if no argument or an incorrect name is provided.
	 
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
		//this creates the keystore, and loads the fog-sub, 01subca and 00root certificate PEMs.
		StoreManagerSingleton sms = StoreManagerSingleton.getInstance(); 
		//
		sms.generateKeyPair();
		//
	}
	
	public void initialise() {
		
	}
	
	/**
	 * Entry point to the application.  
	 * Usage: PMCertManager &#60;CauIP&#91;#58;port number&#93;&#62; &#60;LeaderCauIP&#91;#58;port number&#93;&#62;
	 * <p>
	 * @param args	Application arguments.
	 * @throws Exception 	on error
	 */
	public static void main(String[] args) throws Exception {
		if (args.length < 2) {
			throw new RuntimeException("Usage: PMCertManager <CauIP:port number> <LeaderCauIP:port number>");
		}
		if(args[0].isEmpty() || args[1].isEmpty()) {
			throw new RuntimeException("Usage: PMCertManager <CauIP:port number> <LeaderCauIP:port number>");
		}
		PMCertManager pmCM = new PMCertManager(); //instantiate class
		//cache the values now
		HashMap<String, String> addressesHM = new HashMap<String, String>();
		addressesHM.put("cauIP", args[0]);
		addressesHM.put("leaderCauIP", args[1]);
		LOGGER.debug("Incoming arguments: " + addressesHM.toString());
		//bootstrap the storeManager now
		pmCM.setupStoreManager();
		//start the server to listen to discovery. 
		BasicSocketServer bss = new BasicSocketServer(addressesHM);
		//runs the server which is not threaded.  The control passes to the server.
		bss.runSocket();		
		//
		/*System.exit(0); //9May18 use flag to exit in the BasicSocketServer class and this method returns when 
		bss.runSocket() returns*/
	}

}
