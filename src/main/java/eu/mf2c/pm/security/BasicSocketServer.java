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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;

import org.apache.log4j.Logger;

import eu.mf2c.pm.security.Exception.BasicSocketServerException;
import eu.mf2c.pm.security.Exception.StoreManagerSingletonException;

/**
 * A basic socket server to listening to incoming messages.
 * For IT1, we listen to the&#58;
 * <ul>
 * <li>Discovery block triggering the process flow to contact the CAU server to obtain an agent 
 * certificate.</li>
 * <li>Identity block sending device identity info</li>
 * </ul> * 
 * <p>
 * @author Shirley Crompton
 * @email  shirley.crompton@stfc.ac.uk
 * @org Data Science and Technology Group,
 *      UKRI Science and Technology Council
 * @Created 6 Apr 2018
 * <p>
 */
public class BasicSocketServer {
	/** Message logger attribute */
	protected Logger LOGGER = Logger.getLogger(BasicSocketServer.class.getName());
	/** server socket object */
	public ServerSocket s = null;
	/** socket object */
    public Socket conn = null;
    /** Buffered reader object for reading client input */
    public BufferedReader inReader = null;
    /** Collection of input values from the Discovery block */
    private HashMap<String, String> cache = new HashMap<String,String>();
    
    /*
     * Construct an instance.
     * <p>
     * @param hm 	A {@link java.util.HashMap <em>HashMap</em>} representations of the CAU IP addresses.
     */
    public BasicSocketServer(HashMap<String, String> hm) {
    	this.cache.putAll(hm);; //store a ref to the parent
    }
    
    
    /**
     * Runs a basic TCP&#47;IP socket server to listen for
     * trigger from the Discovery block and receive the required
     * identity and leader information.
     * <p> 
     * @throws Exception 
     */
    public void runSocket() throws Exception {
    	//no thread here, as we only needs to listen to discovery block
        s = new ServerSocket(0 , 2, InetAddress.getByName("127.0.0.1")); //auto port n#, max 2 connections, local host
        //add a shutdown hook for when user terminates JVM
        Runtime.getRuntime().addShutdownHook(new Thread(){public void run(){
            try {
            	shutdown(); //JVM will always close socket and streams anyway
                LOGGER.info("The basic socket server is shutting down!");
                System.out.print("The basic socket server is shutting down.....");
                StoreManagerSingleton.getInstance().persistKeyStore();
                //
            } catch (IOException | StoreManagerSingletonException e) { /* failed */ 
            	LOGGER.error("Error shutting down socket: " + e.getMessage());
			}
        }});
        //       
        LOGGER.info("Socket running on port : " + s.getLocalPort() + ", waiting for connection");
        try {
        	while(true) { //infinite loop
		        //get the connection socket
		        conn = s.accept(); //connection blocks
		        LOGGER.debug("Connection received from " + conn.getInetAddress().getHostName() + " : " + conn.getPort());
		        //set up input read
		        inReader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
		        //read in a Base64 encoded Json String
		        String base64String = inReader.readLine();
		        String message = new String(Base64.getDecoder().decode(base64String),StandardCharsets.UTF_8);
		        //
		        this.getValues(message);
		        //now we got all the values, spawn a thread to do the CAU interaction
		        CauClient client = new CauClient(this.cache); //may throw exceptions on instantiation
		        client.start();
        	}
        }finally {
        	this.shutdown();
        }
    }
    /** 
     * Shut down socket server and release resources.
     * <p> 
     * @throws IOException on error
     */
    public void shutdown() throws IOException {
    	inReader.close();
        s.close();
    }
    /**
     * Parse the incoming message String and get the attribute
     * values.  The message contains values which are represented 
     * as key&#45;value pairs, with each pair separated by a &#39;,&#39; 
     * <p>
     * @param message
     * @throws BasicSocketServerException 
     */
    private void getValues(String message) throws BasicSocketServerException {
    	//tokenise message
    	//E.g.: leaderID=ablcidek1234;LeaderMacAddr=00-14-22-01-23-45;idKey=12345678-1234-5678-1234-567812345678;deviceId=00-14-22-01-23-45
    	String[] msgList = message.split(";");
    	for (String entry : msgList) {
    		  String[] keyValue = entry.split("=");
    		  this.cache.put(keyValue[0],keyValue[1]);
    	}
    	if(cache.size() != 6) {//2 ip addresses + 4 here
    		throw new BasicSocketServerException("Incorrect number of values received! Cannot continue.");
    	}
    }

	

}