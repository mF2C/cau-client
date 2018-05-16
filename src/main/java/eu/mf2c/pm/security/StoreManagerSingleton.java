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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
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
 * @author Shirley Crompton, shirley.crompton@stfc.ac.uk
 * org Data Science and Technology Group,
 *     UKRI Science and Technology Council
 * Date 10 Apr 2018
 */
public class StoreManagerSingleton {
	
	/** Logger attribute */
	protected static Logger LOGGER = Logger.getLogger(StoreManagerSingleton.class);
	/** An instance of the class */
	private static StoreManagerSingleton instance = null;
	/** A password String to protected the keystore */
	private static final String STOREPASS = "stfc-mf2c-jkspass";
	/** A password String to protected the truststore */
	private static final String TRUSTPASS = "changeit";
	/** A password String to protected the key entry */
	private static final String KEYPASS = "stfc-mf2c-key"; //appended with the fog-id
	/** A JKS keystore for private credentials */
	private static KeyStore keyStore;
	/** A JKS keystore for cacerts */
	private static KeyStore trustStore;
	/** A runtime cache of X.509 certificates 
	private static X509Certificate[] certCache;*/
	//for idKey, deviceId, leaderId, leaderMacAddr (each set of IDs are prefixed by the fog-ID [for post-IT1])
	/** Temporary cache of fog identities 
	private static HashMap<String, String> identities = new HashMap<String, String>();*/
	/** file name of the persisted trustStore */
	private static final String CACERT_PATH = "mF2Ccacert.jks";
	/** file name of the persisted keyStore */
	private static final String STORE_PATH = "mF2Cjks.jks";
	/** RSA keypair attribute for owner agent */
	private KeyPair keypair = null;
	/** Secure random number generator attribute */
	private static SecureRandom random = new SecureRandom();
	
	
	
	/** 
	 * private constructor 
	 * @throws StoreManagerSingletonException on error
	 * */
	private StoreManagerSingleton() throws StoreManagerSingletonException{		
			createTrustStore();
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
	 * Getter for the {@link StoreManagerSingleton#trustStore <em>trustStore</em>} attribute
	 * <p>
	 * @return	the {@link StoreManagerSingleton#trustStore <em>trustStore</em>} attribute
	 */
	public KeyStore getTrustStore() {
		return trustStore;
	}
	/**
	 * Getter for the {@link StoreManagerSingleton#keyStore <em>keyStore</em>} attribute
	 * <p>
	 * @return	the {@link StoreManagerSingleton#keyStore <em>keyStore</em>} attribute
	 */
	public KeyStore getKeyStore() {
		return keyStore;
	}
	
	/**
	 * Get the keystore password.
	 * <p>
	 * @return the password
	 */
	public String getStorePass() {
		return STOREPASS;
	}
	/**
	 * Load a X.509 certificate from the provided input stream
	 * <p>
	 * @param inStream 	an input stream to the PEM file
	 * @return	the generated X.509 certificate or null if there is an error.
	 */
	public X509Certificate generateCertfromPEM(InputStream inStream) {
		X509Certificate ca = null;
		//
		try {
	        CertificateFactory cf = CertificateFactory.getInstance("X.509");
			//
			ca = (X509Certificate) cf.generateCertificate(inStream);
		} catch (CertificateException e) {
			// 
			LOGGER.error("CertificateException generating certificate from file: " + e.getMessage());
		} finally{
			try {
				inStream.close();
			}catch (IOException e) {
				//too bad
				LOGGER.error("IOException generating certificate from file: " + e.getMessage());
			}
		}
        return ca;
		
	}
	/**
	 * Generate a X.509 certificate from a byte array representation.
	 * <p>
	 * @param bytes	containing the X.509 certificate
	 * @return	generated X509 certificate object or null if there is an error.
	 */
	public X509Certificate generateCertFromBytes(byte[] bytes) {
		X509Certificate cert = null;
		//"resource\\X509.pem"
		try {
	        CertificateFactory cf = CertificateFactory.getInstance("X.509");
			//
			cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(bytes));
		} catch (CertificateException e) {
			// 
			LOGGER.error("CertificateException generating certificate from byte[] : " + e.getMessage());
		}
        return cert;
	}
	/**
	 * Write the keystore and truststore to files.
	 * <p>
	 * @throws StoreManagerSingletonException on processing errors
	 */
	public void persistKeyStores() throws StoreManagerSingletonException {
		File file = null;
		try {
			//trustStore
			if(trustStore.size() < 1) {
				LOGGER.info("No entries in the trustStore, aborting writing to file.");
			}
			file = new File(CACERT_PATH);
			if(!file.exists()) {
				file.createNewFile();
			}
			//file is appended to if exist
		    trustStore.store(new FileOutputStream(file), TRUSTPASS.toCharArray());
		    //keyStore
		    if(keyStore.size() < 1) {
				LOGGER.info("No entries in the keyStore, aborting writing to file.");
			}
			file = new File(STORE_PATH);
			if(!file.exists()) {
				file.createNewFile();
			}
			//file is appended to if exist
		    keyStore.store(new FileOutputStream(file), STOREPASS.toCharArray());
		} catch (KeyStoreException| NoSuchAlgorithmException | CertificateException |IOException e ) {
			LOGGER.error("Error writing store to file(" + file.getPath() + ": " + e.getMessage());
			throw new StoreManagerSingletonException("Error writing store to file" + file.getPath() + ": " + e.getMessage());
		} 
	}
	
	/**
	 * Store a X.509 certificate with the alias.
	 * <p>
	 * @param alias	A {@link java.lang.String <em>String</em>} representation of the certificate alias
	 * @param cert	An X.509 certificate
	 * @throws StoreManagerSingletonException	if certificate is null or on storing the certificate
	 */
	public void storeCertificate(String alias, X509Certificate cert) throws StoreManagerSingletonException {
		if(cert == null) {
			throw new StoreManagerSingletonException("Cannot load null certificate with alias " + alias + "!");
		}else {
			try {
				trustStore.setCertificateEntry(alias, cert);
			}catch(KeyStoreException ke) {				
				throw new StoreManagerSingletonException("KeystoreException loading certificate with alias " + alias + "! " + ke.getMessage());
			}
		}
				
	}
	/**
	 * Store a X.509 certificate, along with its alias, the private key and the certificate chain.
	 * <p>
	 * @param alias		A {@link java.lang.String <em>String</em>} representation of the certificate alias
	 * @param fogID		A {@link java.lang.String <em>String</em>} representation of the ID of the target fog
	 * @param cert		The certificate associated with the private key for the entry.
	 * @throws KeyStoreException	On error storing the key entry.
	 */
	public void storeKeyEntry(String alias, String fogID, X509Certificate cert) throws KeyStoreException {
		//hard coding the certificate chain for IT1 demo
		List<X509Certificate> mylist = new ArrayList<X509Certificate>();
		mylist.add(cert); //the certificate associated with the private key last (entity cert)
		mylist.add((X509Certificate) trustStore.getCertificate("fog-sub"));
		//mylist.add((X509Certificate) trustStore.getCertificate("fog-sub"));
		//mylist.add((X509Certificate) trustStore.getCertificate("00root"));
		X509Certificate[] chain = (X509Certificate[]) mylist.toArray(new X509Certificate[mylist.size()]);
		LOGGER.debug("About to store the end-entity cert with the fog ca cert as chain....");
		//keypass is the passphrase to the cert
		keyStore.setKeyEntry(alias, this.keypair.getPrivate(), (KEYPASS+fogID).toCharArray(), chain);
		
	}
	/**
	 * Retrieve a keystore entry by the provided alias.
	 * <p>
	 * @param alias		the entry alias
	 * @param fogID		the fog identity which forms part of the entry passphrase
	 * @return			the retrieved 
	 * @throws Exception if the specified entry is not a PrivateKeyEntry or an incorrect passphrase is provided
	 */
	public PrivateKeyEntry getKeyEntry(String alias, String fogID) throws Exception{
		if(keyStore.entryInstanceOf(alias,KeyStore.PrivateKeyEntry.class)){
			LOGGER.debug("About to retrieve the keystore entry with alias = " + alias);
			ProtectionParameter protParam = new KeyStore.PasswordProtection((KEYPASS+fogID).toCharArray());
			return (PrivateKeyEntry) keyStore.getEntry(alias, protParam);
			
		}else {
			throw new StoreManagerSingletonException("Entry(" + alias + ") is not a PrivateKeyEntry!");
		}
		 
	}
	
	/**
	 * Create a TrustStore using the predefined file name.  If the file exists, load it.  Else,
	 * create a new one and write it to file.
	 * The method also loads the bundled certificate PEMs to the store.
	 * <p>
	 * @throws StoreManagerSingletonException on error creating the keystore or on loading the 
	 * 					certificate PEMs.
	 */
	public void createTrustStore() throws StoreManagerSingletonException {
		File file = new File(CACERT_PATH);
		try {
			trustStore = KeyStore.getInstance("JKS");		
		    if (file.exists()) {
		        // if exists, load		        
				trustStore.load(new FileInputStream(file), TRUSTPASS.toCharArray());
		    } else {
		        // if not exists, create it
		    	LOGGER.debug("Creating the new truststore(" + CACERT_PATH + ")");
		        trustStore.load(null, TRUSTPASS.toCharArray()); //initialise
		        trustStore.store(new FileOutputStream(file), TRUSTPASS.toCharArray());
		    }
		    //9May18 updated to use the new CA cert 14May loaded untrust and fog ca public keys
		    storeCertificate("fog-sub",generateCertfromPEM(this.getClass().getResourceAsStream("/ca_fog.pem")));
		    storeCertificate("ut-sub",generateCertfromPEM(this.getClass().getResourceAsStream("/ca_untrust.pem")));
		    //storeCertificate("fog-sub",generateCertfromPEM(this.getClass().getResourceAsStream("/fog-sub.pem")));
		    //storeCertificate("01subca",generateCertfromPEM(this.getClass().getResourceAsStream("/01subca.pem")));
		    //storeCertificate("00root",generateCertfromPEM(this.getClass().getResourceAsStream("/00root.pem")));
		    
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			LOGGER.error("Error writing keystore file : " + e.getMessage());
			throw new StoreManagerSingletonException("Error writing keystore file : " + e.getMessage());
		}
	}
	
	/**
	 * Create a KeyStore using the predefined file name.  If the file exists, load it.  Else,
	 * create a new one and write it to file.
	 * <p>
	 * @throws StoreManagerSingletonException on error creating the keystore.
	 */
	public void createKeyStore() throws StoreManagerSingletonException {
		File file = new File(STORE_PATH);
		try {
			keyStore = KeyStore.getInstance("JKS");		
		    if (file.exists()) {
		        // if exists, load
		    	LOGGER.debug("keystore exists: loading file from " + STORE_PATH);
		    	//LOGGER.debug("storepass: " + STOREPASS);
				keyStore.load(new FileInputStream(file), STOREPASS.toCharArray());
		    } else {
		        // if not exists, create it
		    	LOGGER.debug("Creating the new Keystore(" + STORE_PATH + ")");
		        keyStore.load(null, STOREPASS.toCharArray()); //initialise
		        keyStore.store(new FileOutputStream(file), STOREPASS.toCharArray());
		    }
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			LOGGER.error("Error writing keystore file : " + e.getMessage());
			throw new StoreManagerSingletonException("Error writing keystore file : " + e.getMessage());
		}
	}
	/**
	 * Generate a PKCS10 Certification Request.
	 * <p>
	 * @param  cn  The certificate common name
	 * @return the generated request object.
	 * @throws StoreManagerSingletonException on processing errors
	 */
	public PKCS10CertificationRequest createCSR(String cn) throws StoreManagerSingletonException{
		PKCS10CertificationRequest csr = null;
		//keypair generated by the PMCertManager
		PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
		    new X500Principal("CN=" + cn + ", OU=Fog IT1, O=mF2C, C=EU "), keypair.getPublic());
		JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
		ContentSigner signer;
		try {
			signer = csBuilder.build(keypair.getPrivate());
			csr = p10Builder.build(signer);
			//X500Name name = csr.getSubject();
			LOGGER.debug("The DN: " + csr.getSubject().toString());
		} catch (OperatorCreationException e) {
			LOGGER.error("Error generating CSR: " + e.getMessage());
			throw new StoreManagerSingletonException("Error generating CSR: " + e.getMessage());
		}
		return csr;
		
	}
	/**
	 * Generate a CSR, get a {@link java.lang.String <em>String</em>} representation of it.
	 * <p>	 * 
	 * @param  cn  The certificate common name
	 * @return	a {@link java.lang.String <em>String</em>} representation of the CSR.
	 * @throws StoreManagerSingletonException on processing error.
	 */
	public String createCSRString(String cn) throws StoreManagerSingletonException{
		JcaPEMWriter pw = null;
		String s = null;
		try {
			PKCS10CertificationRequest csr = createCSR(cn);
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
	public void generateKeyPair() throws StoreManagerSingletonException {
		//you sign your CSR with the private key and once you get the certificate back from the CA
		//your private key is stored together with the certificate as a keyEntry
		KeyPairGenerator keyGen;
		try {
			keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(2048, random);
			//keyGen.initialize(2048);
			this.keypair = keyGen.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			LOGGER.error("Error generating RSA keypair: " + e.getMessage());
			throw new StoreManagerSingletonException("NoSuchAlgorithm Error generating RSA keypair: " + e.getMessage());
		}
	}
	

	/**
	 * @param args
	 
	public static void main(String[] args) {
		// TODO Auto-generated method stub

	}*/

}
