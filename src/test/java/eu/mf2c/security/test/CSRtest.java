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
package eu.mf2c.security.test;

import static org.junit.Assert.*;

import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import eu.mf2c.security.Exception.StoreManagerSingletonException;
import eu.mf2c.security.cc.StoreManagerSingleton;

/**
 * Test generating a CSR {@link java.lang.String <em>String</em>}
 * <p>
 * @author Shirley Crompton
 * @email  shirley.crompton@stfc.ac.uk
 * @org Data Science and Technology Group,
 *      UKRI Science and Technology Council
 * @Created 30 May 2019
 * <p>
 */
@Ignore
public class CSRtest {
	/** Logger attribute */
	protected static Logger LOGGER = Logger.getLogger(CSRtest.class);
	/** device id which is used as the CN */
	private static String deviceId;

	/**
	 * {@inheritDoc}
	 */
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		//CN = 64 char length
		deviceId = "c6968d75a7df20e2d2f81f87fe69bf0b7dd14f4a22cca5f15ffc645cb4d45944bfdc7a7a970a9e13a331161e304a3094d8e6e362e88bd7df0d7b5473b6d2aa80".substring(0, 63);
		
	}

	/**
	 * {@inheritDoc}
	 */
	@AfterClass
	public static void tearDownAfterClass() throws Exception {
		deviceId = null;
	}

	/**
	 * {@inheritDoc}
	 */
	@Before
	public void setUp() throws Exception {
	}

	/**
	 * {@inheritDoc}
	 */
	@After
	public void tearDown() throws Exception {
	}
	/**
	 * Test generating a {@link java.lang.String <em>String</em>} representation of
	 * a CSR
	 */
	@Test
	public void testCreateCSR() {
		
		try {
			StoreManagerSingleton.getInstance().generateKeyPair();
			String csrString = StoreManagerSingleton.getInstance().createCSRString(deviceId);
			LOGGER.debug("Created CSR String : " + csrString);			
		} catch (StoreManagerSingletonException e) {
			fail("Error creating CSR String: " + e.getMessage());
		}
		
	}

}
