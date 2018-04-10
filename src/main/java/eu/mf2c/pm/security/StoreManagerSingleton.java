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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.HashMap;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import eu.mf2c.pm.security.Exception.StoreManagerSingletonException;

/**
 * A singleton class responsible for the trust and key stores.  
 * On application close down, the stores are written to a local file.
 * <p>
 * @author Shirley Crompton
 * @email  shirley.crompton@stfc.ac.uk
 * @org Data Science and Technology Group,
 *      UKRI Science and Technology Council
 * @Created 10 Apr 2018
 */
public class StoreManagerSingleton {
	
	/** Logger attribute */
	protected static Logger LOGGER = Logger.getLogger(StoreManagerSingleton.class);
	/** An instance of the class */
	private static StoreManagerSingleton instance = null;
	/** A password String to protected the keystore */
	private static final String STOREPASS = "stfc-mf2c"+Instant.now().getNano(); 
	/** A password String to protected the key entry */
	private static final String KEYPASS = "stfc-mf2c"; //appended with the fog-id
	/** A JKS keystore */
	private static KeyStore keystore;
	/** A runtime cache of X.509 certificates */
	private static X509Certificate[] certCache;
	//for idKey, deviceId, leaderId, leaderMacAddr (each set of IDs are prefixed by the fog-ID [for post-IT1])
	/** Temporary cache of fog identities */
	private static HashMap<String, String> identities = new HashMap<String, String>();
	/** file name of the persisted keystore */
	private static final String STORE_PATH = "mF2CJKS.jks";
	/** RSA keypair attribute for owner agent */
	private static KeyPair keypair = null;
	/** Secure random number generator attribute */
	private static SecureRandom random = new SecureRandom();
	
	
	
	/** 
	 * private constructor 
	 * @throws StoreManagerSingletonException 
	 * */
	private StoreManagerSingleton() throws StoreManagerSingletonException{		
			createKeyStore();
	}
	/**
	 * Get an instance.  Create a new one if not yet instantiated.
	 * A JKS keystore is created during instantiation. 
	 * <p>
	 * @return an instance of the class.
	 * @throws StoreManagerSingletonException  on error instantiating the instance.
	 */
	public static StoreManagerSingleton getInstance() throws StoreManagerSingletonException {
		if(instance == null) {
			instance = new StoreManagerSingleton();
		}
		return instance;
				
	}
	/**
	 * Load a X.509 certificate from file.
	 * <p>
	 * @param	relative path to the file
	 * @return	the generated X.509 certificate
	 */
	public X509Certificate loadPemFile(String path) {
		X509Certificate ca = null;
		//"resource\\X509.pem"
		try (FileInputStream inStream = new FileInputStream(new File(path))) {
	        CertificateFactory cf = CertificateFactory.getInstance("X.509");
			//
			ca = (X509Certificate) cf.generateCertificate(inStream);
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        return ca;
		
	}
	/**
	 * Write the keystore to file.
	 * <p>
	 * @throws StoreManagerSingletonException on processing errors
	 */
	public void persistKeyStore() throws StoreManagerSingletonException {
		try {
			if(keystore.size() < 1) {
				LOGGER.info("No entries in the keystore, aborting writing to file.");
			}
		File file = new File(STORE_PATH);
			//file is appended to if exist
		    keystore.store(new FileOutputStream(file), STOREPASS.toCharArray());
		    
		} catch (KeyStoreException| NoSuchAlgorithmException | CertificateException |IOException e ) {
			LOGGER.error("Error writing keystore file : " + e.getMessage());
			throw new StoreManagerSingletonException("Error writing keystore file : " + e.getMessage());
		} 
	}
	
	/**
	 * Store a X.509 certificate with the alias.
	 * @param alias	A {@link java.lang.String <em>String</em>} representation of the certificate alias
	 * @param cert	An X.509 certificate
	 * @throws KeyStoreException	on storing the certificate
	 */
	public static void storeCertificate(String alias, X509Certificate cert) throws KeyStoreException {
		keystore.setCertificateEntry(alias, cert);		
	}
	/**
	 * Store a X.509 certificate, along with its alias and the private key which is protected by the
	 * pre-defined password.
	 * <p>
	 * @param alias		A {@link java.lang.String <em>String</em>} representation of the certificate alias
	 * @param privKey	RSA private key associated with the certificate.
	 * @param chain		An array of X.509 certificates containing the certificate chain for the provided 
	 * 					certificate
	 * @param fogID		A {@link java.lang.String <em>String</em>} representation of the ID of the target fog
	 * @throws KeyStoreException	On error storing the key entry.
	 */
	public static void storeKeyEntry(String alias, PrivateKey privKey, X509Certificate[] chain, String fogID) throws KeyStoreException {
		keystore.setKeyEntry(alias, privKey, (KEYPASS+fogID).toCharArray(), chain);
	}
	/**
	 * Create the Keystore using the predefined file name.  If the file exists, load it.  Else,
	 * create a new keystore and write it to file.
	 * <p>
	 * @throws StoreManagerSingletonException
	 */
	public static void createKeyStore() throws StoreManagerSingletonException {
		File file = new File(STORE_PATH);
		try {
			keystore = KeyStore.getInstance("JKS");		
		    if (file.exists()) {
		        // if exists, load		        
				keystore.load(new FileInputStream(file), STOREPASS.toCharArray());
		    } else {
		        // if not exists, create
		        keystore.load(null, null);
		        keystore.store(new FileOutputStream(file), STOREPASS.toCharArray());
		    }
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			LOGGER.error("Error writing keystore file : " + e.getMessage());
			throw new StoreManagerSingletonException("Error writing keystore file : " + e.getMessage());
		}
	}
	/**
	 * Generate a PKCS10 Certification Request.
	 * <p>
	 * @return the generated request object.
	 */
	public static PKCS10CertificationRequest createCSR() throws StoreManagerSingletonException{
		PKCS10CertificationRequest csr = null;
		
		PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
		    new X500Principal("CN=" + identities.get("deviceID") + ", OU=Fog IT1, O=mF2C, C=EU "), keypair.getPublic());
		JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
		ContentSigner signer;
		try {
			signer = csBuilder.build(keypair.getPrivate());
			csr = p10Builder.build(signer);
			X500Name name = csr.getSubject();
			LOGGER.debug("The DN: " + name.toString());
		} catch (OperatorCreationException e) {
			LOGGER.error("Error generating CSR: " + e.getMessage());
			throw new StoreManagerSingletonException("Error generating CSR: " + e.getMessage());
		}
		return csr;
		
	}
	/**
	 * Generate a CSR, get a {@link java.lang.String <em>String</em>} representation of it.
	 * ,p>
	 * @return	a {@link java.lang.String <em>String</em>} representation of the CSR.
	 * @throws StoreManagerSingletonException on processing error.
	 */
	public static String createCSRString() throws StoreManagerSingletonException{
		JcaPEMWriter pw = null;
		String s = null;
		try {
			PKCS10CertificationRequest csr = createCSR();
			StringWriter sw = new StringWriter();
			pw = new JcaPEMWriter(sw);	        
			pw.writeObject(csr);
			pw.flush();
			//			
			s = sw.toString();
		} catch (IOException e) {
			//
			LOGGER.info("Error converting CSR to String: " + e.getMessage());
			throw new StoreManagerSingletonException("Error converting CSR to String: " + e.getMessage());
		} finally {
			try {
				pw.close();
			} catch (IOException e) {
				// swallow it
				LOGGER.info("Error closing jcaPEMWriter buffer stream....");
			}
		}
        return s;
	}
	/**
	 * Generate RSA keypair for the agent.
	 * <p>
	 * @throws StoreManagerSingletonException if no such algorithm encountered.
	 */
	public static void generateKeyPair() throws StoreManagerSingletonException {
		
		KeyPairGenerator keyGen;
		try {
			keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(2048, random);
			//keyGen.initialize(2048);
			keypair = keyGen.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			LOGGER.error("Error generating RSA keypair: " + e.getMessage());
			throw new StoreManagerSingletonException("Error generating RSA keypair: " + e.getMessage());
		}
	}
	

	/**
	 * @param args
	 
	public static void main(String[] args) {
		// TODO Auto-generated method stub

	}*/

}
