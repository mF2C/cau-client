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

import java.net.HttpURLConnection;
import java.net.URL;

import org.apache.log4j.Logger;

/**
 * A basic http client to message the local Categorisation
 * block to trigger the agent categorisation process.
 * The Categorisation block is assumed to reside on the
 * localhost.
 * <p>
 * @author Shirley Crompton
 * @email  shirley.crompton@stfc.ac.uk
 * @org Data Science and Technology Group,
 *      UKRI Science and Technology Council
 * @Created 17 Apr 2018
 * <p>
 */
public class HttpURLClient extends Thread {
	/** message logger attribute */
	protected Logger LOGGER = Logger.getLogger(HttpURLClient.class);
	//localhost/api/categorisation?deviceID=agentDeviceID
	/** categorisation block ReST endpoint attribute */
	public final String ENDPOINT = "http://localhost/api/categorisation";
	/** agent device ID attribute */
	public String deviceID = null;
	/** agent id key */
	public String idKey = null;
	
	/**
	 * Constructor
	 * <p>
	 * @param agentDeviceID		the agent&#39;s device id
	 * @param key				the agent&#39;s id key
	 */
	public HttpURLClient(String agentDeviceID, String key) {
		this.deviceID = agentDeviceID;
		this.idKey = key;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void run() {
		try {
			String url = this.ENDPOINT + "?deviceID=" + this.deviceID;
			LOGGER.debug("The categorisation ReST endpoint: " + url);
			URL obj = new URL(url);
			HttpURLConnection con = (HttpURLConnection) obj.openConnection();	
			// optional default is GET
			con.setRequestMethod("GET");	
			//add request header
			con.setRequestProperty("User-Agent", "mF2C/IT1 CauClient-" + this.idKey + "/IT1");
			LOGGER.debug("\nSending 'GET' request to URL : " + url);
			int responseCode = con.getResponseCode();
			LOGGER.debug("Response Code : " + responseCode);
			if(responseCode != 200) {
				throw new Exception("Categorisation ReST service returned " + responseCode + "!");
			}
			LOGGER.debug("Triggered Categorisation block to start categorisation.\n");
			LOGGER.info("Completed IT1 CAU client trigger dependencies responsibilities.......");			
		}catch(Exception e) {
			String msg = "Error running HttpURLClient: " + e.getMessage();
			LOGGER.error(msg);
			Thread thread = Thread.currentThread();
			thread.getUncaughtExceptionHandler().uncaughtException(thread, new Exception(msg));
		}

	}
	//no further action required for IT1
}
