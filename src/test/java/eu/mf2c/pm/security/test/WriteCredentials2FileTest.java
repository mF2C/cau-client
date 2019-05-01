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
package eu.mf2c.pm.security.test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.LocalDate;
import java.time.Period;
import java.time.ZoneOffset;
import java.util.Date;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import eu.mf2c.pm.security.Exception.StoreManagerSingletonException;

import static org.junit.Assert.*;

/**
 * Unit test for writing the private key and agent certificate to 
 * file.
 * <p>
 * @author Shirley Crompton
 * email  shirley.crompton@stfc.ac.uk
 * org Data Science and Technology Group,
 *      UKRI Science and Technology Council
 * Created 18 Feb 2019
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class WriteCredentials2FileTest {

	/** Message Logger */
	protected static Logger LOGGER = LogManager.getLogger(WriteCredentials2FileTest.class);
	/** Secure random number generator attribute */
	private static SecureRandom random;
	/** RSA keypair */
	private static KeyPair keypair;
	/** Location of credential folder 
	private static String dataPath = File.separator + "pkidata" + File.separator;*/
	
	/**
	 * @throws java.lang.Exception on errors
	 */
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		random = new SecureRandom();
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	/**
	 * @throws java.lang.Exception on errors
	 */
	@AfterClass
	public static void tearDownAfterClass() throws Exception {
		random = null;
		keypair = null;
	}

	
	/**
	 * Test writing the private key file.
	 */
	@Test
	public void testAWritingPrivateKeyFile() {		
		this.genKeyPair();
		if(keypair != null) {
			this.writeKeyFile();				
		}
	}
	/**
	 * Test writing the certificate file
	 */
	@Test
	public void testBWritingCertificateFile() {
		if(keypair != null) {
			X509Certificate cert = this.getSelfSignedCert();
			if(cert != null) {
				this.writeCertFile(cert);
			}			
		}else {
			fail("Can't write cert file, no keypair!");
		}
	}
	
	///////////////////////////private methods/////////////////////////////
	/**
	 * Generate an RSA {@link java.security.KeyPair <em>KeyPair</em>} of 2048 length
	 */
	private void genKeyPair() {
		try {
			KeyPairGenerator keyGen;
			keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(2048, random);
			keypair = keyGen.generateKeyPair();
		}catch(Exception e) {
			fail("Error generating key pair : " + e.getMessage());
		}		
	}		
	/**
	 * Write the agent&#39;private key to file.
	 */
	private void writeKeyFile() {		
		//18Feb2019 write the private key as pem to /pkidata/server.key
		String absPath = File.separator + "pkidata" + File.separator + "server.key";
		System.out.println("the private key file target : " + absPath);
		LOGGER.debug("the private key file target : " + absPath);
		try (PemWriter pw = new PemWriter(new OutputStreamWriter(new FileOutputStream(absPath)))) {
			// the description is used : BEGIN <description> in the PEM file
			pw.writeObject(new PemObject("RSA PRIVATE KEY", keypair.getPrivate().getEncoded()));
			pw.close();
		}catch(Exception e) {
			fail("Error writing private key to /pkidata/server.key:" + e.getMessage());
		}
	}
	/**
	 * Write the agent&#39;certificate to file.
	 * <p>
	 * @param agentCert&#39;certificate
	 */
	private void writeCertFile(X509Certificate agentCert) {
		//18Feb2019 write the agent's X509 certiciate as pem to /pkidata/server.crt
		String fileName = File.separator + "pkidata" + File.separator + "server.crt";
		System.out.println("the X509 file target : " + fileName);
		LOGGER.debug("the X509 file target : " + fileName);
		//PemWriter pw = new PemWriter(new OutputStreamWriter(new FileOutputStream(fileName)));
		try (PemWriter pw = new PemWriter(new OutputStreamWriter(new FileOutputStream(fileName)))) {
			// the description is used in the PEM file: BEGIN <description> .....
			pw.writeObject(new PemObject("CERTIFICATE", agentCert.getEncoded()));
			pw.close();
		} catch (Exception e) {
			fail("Error writing agent certificate to /pkidata/server.crt:" + e.getMessage());
		}
	}
	/**
	 * Generate a self&#45;signed X.509 certificate.
	 * <p>
	 * @return the generated certificate
	 */
	private X509Certificate getSelfSignedCert() {
		// fill in certificate fields
		X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
		nameBuilder.addRDN(BCStyle.CN, "Agent 0");
		nameBuilder.addRDN(BCStyle.C, "EU"); // country
		nameBuilder.addRDN(BCStyle.OU, "STFC");// orgunit
		nameBuilder.addRDN(BCStyle.O, "mF2C");// org
		nameBuilder.addRDN(BCStyle.L, "Warrington");// locality, city
		nameBuilder.addRDN(BCStyle.EmailAddress, "shirley.crompton@stfc.ac.uk");
		X500Name x500Name = nameBuilder.build();	
		// start date
		LocalDate startDate = LocalDate.now();
		// end date 3 years from now
		Period period = Period.ofYears(1);
		LocalDate endDate = startDate.plus(period);
		// create the 509v3 certificate: issuer, serial, notBefore, notAfter, locale,
		// subject, publickey info
		// bouncy castle classes deprecated as of Nov 2017
		JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(x500Name, // issuer
				new java.math.BigInteger(String.valueOf(Instant.now().getEpochSecond())),
				Date.from(startDate.atStartOfDay(ZoneOffset.UTC).toInstant()),
				Date.from(endDate.atStartOfDay(ZoneOffset.UTC).toInstant()), x500Name, // holder
				keypair.getPublic());

		// build BouncyCastle certificate
		ContentSigner signer;
		try {
			signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(keypair.getPrivate());
			X509CertificateHolder holder = certBuilder.build(signer);
			// convert to JRE certificate
			JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
			converter.setProvider(new BouncyCastleProvider());
			return converter.getCertificate(holder);
		} catch (Exception e) {
			fail("Error generating certificate: " + e.getMessage());
			return null;			
		}
	}

}
