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
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;

import org.apache.log4j.Logger;

import eu.mf2c.security.Exception.CauClientServerException;
import eu.mf2c.security.Exception.StoreManagerSingletonException;

/**
 * A basic socket server to listen to incoming messages.
 * For IT2, the server runs in a loop until shutdown.
 * The server listens to three types of call to&#58;
 * <ul>
 * <li>get a new Agent certificate</li>
 * <li>get an Agent Public Key identified by a device id.</li>
 * <li>register an internal user on the local CIMI instance.</li>
 * </ul>
 * The request is handled synchronously and the server returns
 * either an error message or an OK message.
 * <p>
 * @author Shirley Crompton, shirley.crompton@stfc.ac.uk
 * org Data Science and Technology Group,
 *     UKRI Science and Technology Council
 * Date 29 May 2018
 */
public class CauClientServer {
	/** Message logger attribute */
	protected Logger LOGGER = Logger.getLogger(CauClientServer.class.getName());
	/** server socket object */
	public ServerSocket s = null;
	/** socket object */
    public Socket conn = null;
    /** Buffered reader object for reading client input 
    public BufferedReader inReader = null;
    /** socket server output stream object 
    OutputStream os = null;
    /** Collection of input values from the Policy block 
    private HashMap<String, String> cache = new HashMap<String,String>();*/
    /** flag to control state of socket */
    private boolean isRunning = true;
    
    /*
     * Default constructor
     */
    public CauClientServer() {
    }
    
    
    /**
     * Runs a basic TCP&#47;IP socket server to listen for
     * trigger from the Discovery block and receive the required
     * identity and leader information.
     * <p> 
     * @throws Exception on processing errors
     */
    public void runSocket() throws Exception {
    	//no thread here, as we only needs to listen to discovery block
        //s = new ServerSocket(0 , 2, InetAddress.getByName("127.0.0.1")); //auto port n#, max 2 connections, local host
    	s = new ServerSocket(46065 , 20, InetAddress.getByName("0.0.0.0")); //use ip 0 for container service 8/5/18
        /*add a shutdown hook for when user terminates JVM*/
        Runtime.getRuntime().addShutdownHook(new Thread(){public void run(){
            try {
            	shutdown(); //JVM will always close socket and streams anyway
                LOGGER.info("The basic socket server is shutting down!");
                //System.out.print("The basic socket server is shutting down.....");
                StoreManagerSingleton.getInstance().persistKeyStores();
                //
            } catch (IOException | StoreManagerSingletonException e) { // failed 
            	LOGGER.error("Error shutting down socket: " + e.getMessage());
			}
        }});
        //       
        LOGGER.info("Socket running on port : " + s.getLocalPort() + ", waiting for connection");
        try {
        	while(isRunning) { 
		        //get the connection socket, use request handler thread to process request
        		new CCRequestHandler(s.accept()).start();
				LOGGER.debug("after spawing CauClient reqHandler thread, server returning to waiting....");
				
				
				
				 /*
		        conn = s.accept(); //connection blocks
		        os = conn.getOutputStream();
		        LOGGER.debug("Connection received from " + conn.getInetAddress().getHostName() + " : " + conn.getPort());
		        //set up input read
		        inReader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
		        String message = inReader.readLine(); //9May18 removed base64 encoding
		        LOGGER.debug("Incoming message: " + message);
		        //
		        this.getValues(message);
		        //now we got all the values, spawn a thread to do the CAU interaction
		        CauClient client = new CauClient(this.cache); //may throw exceptions on instantiation		        
		        //9May18 change to a method call		        
		        //client.start();
		        client.run();
		        LOGGER.debug("CauClient returned, about to write OK to policy block ....");		        
		        //if we get to here, the process ran OK otherwise we would be in the exception block
		        os.write("OK".getBytes()); //send OK to policy block
		        //add the shut down for IT1 until we know what's the lifecycle of the Agent
		        this.isRunning = false;
		        //end 9May18*/
        	}
        }catch(Exception e){
        	//this.isRunning = false; //30May19 keeps server going 
        	//Ctrl-C to stop server got handled here so a misleading err4 24July 2019
        	String errMsg = "err4 : " + (e.getMessage() == null ? " unknown error " : e.getMessage());
        	LOGGER.error(errMsg);
        }
        	/*if(os != null) {
        		os.write(errMsg.getBytes());
        	}
        }/*finally {	//30May19 keeps server going        	
        	this.shutdown();
        }*/
    }
    /** 
     * Shut down socket server and release resources.
     * <p> 
     * @throws IOException on error
     */
    public void shutdown() throws IOException {  
    	/*
    	if(inReader != null) {
    		inReader.close();
    	}
    	if(os != null) {
    		os.close();
    	}*/
        s.close();
        /*
        //9May2018 no longer running an infinite loop, moved this from the shutdown hook
        try {
			StoreManagerSingleton.getInstance().persistKeyStores();
		} catch (StoreManagerSingletonException e) {
			// just log the error
			LOGGER.error("Error persisting keystores: " + e.getMessage());			
		}*/
        LOGGER.debug("completed shutdown process....");
    }
    /**
     * Parse the incoming message String and get the attribute
     * values.  The message contains values which are represented 
     * as key&#45;value pairs, with each pair separated by a &#34;,&#34; 
     * <p>
     * @param message  incoming message
     * @throws CauClientServerException on errors
     
    private void getValues(String message) throws CauClientServerException {
    	//tokenise message
    	//E.g.: "detectedLeaderID=56789,deviceID=123456789,IDkey=someIDKey,MACaddr=ab:cd:ef:01:23:45"
    	String[] msgList = message.split(",");
    	for (String entry : msgList) {
    		  String[] keyValue = entry.split("=");
    		  this.cache.put(keyValue[0],keyValue[1]);
    		  LOGGER.debug("cached " + keyValue[0] + ": " + keyValue[1]);
    	}
    	if(cache.size() != 6) {//2 ip addresses + 4 here
    		throw new CauClientServerException("Incorrect number of values received! Cannot continue.");
    	}
    }*/
}
