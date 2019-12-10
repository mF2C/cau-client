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
package eu.mf2c.security.util;

/**
 * Configuration properties.
 * <p>
 * @author Shirley Crompton
 * email  shirley.crompton@stfc.ac.uk
 * org Data Science and Technology Group,
 *      UKRI Science and Technology Council
 * created 31 May 2019
 */
public class Properties {
	
	
	///////////////////////////////////CAU-related/////////////////////////////////////
	/** IP of the local CAU */	//default from docker file
	public static String cauIP = "213.205.14.13:55443"; 
	/** IP of the cloud CAU   //default from docker file TODO not sure if this is still relevant
	public static String CloudCauIP = "127.0.0.1:46410"; */
	public static String cauContext = "/cau";
	/** IP of the Leader
	public static String LeaderIP = "http://example.host/api"; //this is for registering CIMI user  */
	/** IP of the cloud CAU, this offers a fall back if the others are not available */
	public static String cloudCauIP = "213.205.14.13:55443";  //e.g. https://dashboard.mf2c-project.eu/
	/** Agent Type which can be either full or micro 
	public static String agentType = "full"; //default to full, from docker file*/
	/** CAU Rest service path for retrieving a public key by device id */
	public static final String PK = "/publickey"; //resource element for public key 
	/** CAU Rest service path for requesting an Agent certificate */
	public static final String CERT = "/cert"; 
	
	///////////////////////////////////CIMI-related////////////////////////////////////
	/** local CIMI endpoint */
	public static String cimiUrl = "https://cimi/api";
	//ENV CIMI_URL=http://cimi:8201/api  it is an ENV set in the docker file
	/** constant for the CIMI session resource path element 
	public static final String SESSION = "/session";*/
	/** constant for the CIMI user resource path element */
	public static final String USER = "/user";
	
	
	

}
