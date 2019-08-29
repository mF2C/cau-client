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

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;

import eu.mf2c.security.Exception.CauClientServerException;
import eu.mf2c.security.cc.CCRequestHandler;

/**
 * Miscellaneous utility functions.
 * Some functions are based on third parties code
 * <p>
 * @author Shirley Crompton, shirley.crompton@stfc.ac.uk
 * org Data Science and Technology Group,
 *     UKRI Science and Technology Council
 * created 5 Apr 2018
 *
 */
public class Utils {	
	
	/** Message logger attribute */
	protected static Logger LOGGER = Logger.getLogger(Utils.class);
	
	/** Default String value */
	private static String	digits = "0123456789abcdef";
	/* certificate password 
	public static char[] KEY_PASSWD = "keyPassword".toCharArray();
	/** keystore password 
	public static String CLIENT_PASSWORD = "mf2c-client";
	/** truststore password /
	public static String TRUST_STORE_PASSWORD = "mf2c-trust";*/
	
    
	
	/**
	 * Utility method to extract the ip address and port number from the input String.
	 * <p>
	 * @param input	A textual representation of the IP address and optional port number.
	 * @return	a HashMap containing the converted InetAddress representation of the IP and 
	 * 			an integer representation of the port number
	 * @throws UnknownHostException 	on processing error.
	 */
	public static HashMap<String, Object> getAddrProp(String input) throws UnknownHostException, NumberFormatException{
		HashMap<String, Object> props = new HashMap<String, Object>();
		if(input.contains(":")){
			String [] values = input.split(":");
			props.put("ip",InetAddress.getByName(values[0]));
			props.put("port", Integer.parseInt(values[1]));
		}else {
			props.put("ip",InetAddress.getByName(input));
		}		
		return props;
	}
	/**
	 * Parse the input {@link java.lang.String <em>String</em>} for an {@link java.net.InetAddress <em>InetAddress</em>}.
	 * <p>
	 * @param input		A {@link java.lang.String <em>String</em>} representation of A textural IP address 
	 * 					and an optional port number.
	 * @return			The converted {@link java.net.InetAddress <em>InetAddress</em>} object.
	 * @throws UnknownHostException	on conversion error.
	 */
	public static InetAddress getInetAddress(String input) throws UnknownHostException {
		InetAddress addr = null;
		if(input.contains(":")) {
			String [] values = input.split(":");
			addr = InetAddress.getByName(values[0]);
		}else {
			addr = InetAddress.getByName(input);
		}
		return addr;
	}
	/**
	 * Parse the input 	{@link java.lang.String <em>String</em>} for a port number.
	 * @param input		A {@link java.lang.String <em>String</em>} representation of a textural IP address 
	 * 					and an optional port number.
	 * @return			the port number.
	 * @throws NumberFormatException	on conversion error.
	 */
	public static int getPortNum(String input) throws NumberFormatException{
		String [] values = input.split(":");
		return Integer.parseInt(values[1]);
	}
	
    /**
     * Return length many bytes of the passed in byte array as a hex string.
     * 
     * @param data the bytes to be converted.
     * @param length the number of bytes in the data block to be converted.
     * @return a hex representation of length bytes of data.
     */
    public static String toHex(byte[] data, int length)
    {
        StringBuffer	buf = new StringBuffer();
        
        for (int i = 0; i != length; i++)
        {
            int	v = data[i] & 0xff;
            
            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));
        }
        
        return buf.toString();
    }
    
    /**
     * Return the passed in byte array as a hex string.
     * 
     * @param data the bytes to be converted.
     * @return a hex representation of data.
     */
    public static String toHex(byte[] data)
    {
        return toHex(data, data.length);
    }
	
    /**
     * Tokenise a comma&#45;separated {@link java.lang.String <em>String</em>} for
     * the individual parameters. The tokens are key&#45;value pairs, with each 
     * key&#45;value separated by a &#58; 
     * <p>
     * @param message  incoming message {@link java.lang.String <em>String</em>}
     * @return	a {@link java.util.Map <em>Map</em>} of the extracted request parameters	
     */
    public static Map<String, String> getValues(String message) {
    	//tokenise message, for legacy reason, the getCSR request is different from those for registerUser and getPK requests
    	//E.g.: "detectedLeaderID=56789,deviceID=123456789
    	
    	//register user :  adduser=agentdeviceid
    	//get public key : getpubkey=agentdeviceid
    	
    	Map<String, String> map = new HashMap<String, String>();
    	String[] msgList = message.split(",");
    	for (String entry : msgList) {
    		  String[] keyValue = entry.split("=");
    		  map.put(keyValue[0],keyValue[1]); //empty value is not appended!!!  
    	}
    	map.forEach((k,v)->LOGGER.debug(k + " : " + v));
    	return map;
    }
    
	/**
     * Return a string of length len made up of blanks.
     * 
     * @param len the length of the output String.
     * @return the string of blanks.
     */
    public static String makeBlankString(
        int	len)
    {
        char[]   buf = new char[len];
        
        for (int i = 0; i != buf.length; i++)
        {
            buf[i] = ' ';
        }
        
        return new String(buf);
    }
    /**
     * Inner class representing a fixed length random number.
     
	private static class FixedRand extends SecureRandom
    {
        /** version UID attribute 
		private static final long serialVersionUID = 1L;
		MessageDigest	sha;
        byte[]			state;
        
        FixedRand()
        {
            try
            {
                this.sha = MessageDigest.getInstance("SHA-1");
                this.state = sha.digest();
            }
            catch (NoSuchAlgorithmException e)
            {
                throw new RuntimeException("can't find SHA-1!");
            }
        }*/
        /**
         * Generates a user-specified number of random bytes.
         * <p>
         * @param bytes 	bytes array object input
         
	    public void nextBytes(
	       byte[] bytes)
	    {
	        int	off = 0;
	        
	        sha.update(state);
	        
	        while (off < bytes.length)
	        {	            
	            state = sha.digest();
	            
	            if (bytes.length - off > state.length)
	            {
	                System.arraycopy(state, 0, bytes, off, state.length);
	            }
	            else
	            {
	                System.arraycopy(state, 0, bytes, off, bytes.length - off);
	            }
	            
	            off += state.length;
	            
	            sha.update(state);
	        }
	    }
    }*/
    
    /**
     * Return a SecureRandom which produces the same value.
     * @return a fixed random
     
    public static SecureRandom createFixedRandom()
    {
        return new FixedRand();
    }*/
    /**
     * Convert a byte array of 8 bit characters into a String.
     * 
     * @param bytes the array containing the characters
     * @param length the number of bytes to process
     * @return a String representation of bytes
     */
    public static String toString(
        byte[] bytes,
        int    length)
    {
        char[]	chars = new char[length];
        
        for (int i = 0; i != chars.length; i++)
        {
            chars[i] = (char)(bytes[i] & 0xff);
        }
        
        return new String(chars);
    }
    
    /**
     * Convert a byte array of 8 bit characters into a String.
     * 
     * @param bytes the array containing the characters
     * @return a String representation of bytes
     */
    public static String toString(
        byte[]	bytes)
    {
        return toString(bytes, bytes.length);
    }
    
    /**
     * Convert the passed in String to a byte array by
     * taking the bottom 8 bits of each character it contains.
     * <p>
     * @param string the string to be converted
     * @return a byte array representation
     */
    public static byte[] toByteArray(
        String string)
    {
        byte[]	bytes = new byte[string.length()];
        char[]  chars = string.toCharArray();
        
        for (int i = 0; i != chars.length; i++)
        {
            bytes[i] = (byte)chars[i];
        }
        
        return bytes;
    }
}
