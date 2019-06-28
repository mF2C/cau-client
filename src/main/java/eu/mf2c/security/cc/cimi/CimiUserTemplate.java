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
package eu.mf2c.security.cc.cimi;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * CIMI user template bean
 * :todo this needs to be replaced with the new template being developed by SixQ
 * <p>
 * @author Shirley Crompton
 * @email  shirley.crompton@stfc.ac.uk
 * @org Data Science and Technology Group,
 *      UKRI Science and Technology Council
 * @Created 30 May 2019
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class CimiUserTemplate {
	/** nested {@link CimiUser <em>CimiUser</em>} containing user details */
	@JsonProperty("userTemplate")
	private CimiUser user;
	/**
	 * Default constructor
	 */
	public CimiUserTemplate() {
	}
	/**
	 * Construct an instance with user details
	 * <p>
	 * @param user	{@link CimiUser <em>CimiUser</em>} object
	 */
	public CimiUserTemplate(CimiUser user) {
		this.user = user;
	}
	/**
	 * Getter for the nested {@link CimiUser <em>CimiUser</em>} object
	 * <p>
	 * @return the nested {@link CimiUser <em>CimiUser</em>} object
	 */
	public CimiUser getUser() {
		return user;
	}
	/**
	 * Setter for the nested {@link CimiUser <em>CimiUser</em>} object
	 * <p>
	 * @param user {@link CimiUser <em>CimiUser</em>} object
	 */
	public void setUser(CimiUser user) {
		this.user = user;
	}
	/**
	 * Return a {@link java.lang.String <em>String</em>} representation of the
	 * object
	 */
	@Override
	public String toString() {
		return "userTemplate{" + (this.user==null ? "null" : this.user.toString()) + "}";
		
		
	}

	/**
	 * Nested class containing details of the CIMI user
	 * <p>
	 * @author Shirley Crompton
	 * @email shirley.crompton@stfc.ac.uk
	 * @org Data Science and Technology Group, UKRI Science and Technology Council
	 * @Created 30 May 2019
	 */
	@JsonIgnoreProperties(ignoreUnknown = true)
	public static class CimiUser {
		/** CIMI user name attribute */
		@JsonProperty("username")
		private String name;
		/** CIMI user password attribute which must be longer than 8 chars*/
		private String password;
		/** CIMI user password repeat attribute */
		private String passwordRepeat;
		/** CIMI user email address attribute */
		private String emailAddress;
		/** CIMI href attribute */
		private String href; // "user-template/self-registration";

		/**
		 * Construct an instance
		 */
		public CimiUser() {
		}

		/**
		 * Getter for the CIMI username attribute
		 * <p>
		 * 
		 * @return the CIMI username attribute
		 */
		public String getName() {
			return name;
		}

		/**
		 * Getter for the CIMI href attribute
		 * 
		 * @return the hREF attribute
		 */
		public String getHref() {
			return href;
		}

		/**
		 * Setter for the CIMI href attribute
		 * 
		 * @param href
		 */
		public void setHref(String href) {
			this.href = href;
		}

		/**
		 * Getter for the CIMI user password attribute
		 * 
		 * @return the password
		 */
		public String getPassword() {
			return password;
		}

		/**
		 * Setter for the CIMI user password attribute.
		 * The password must be at last 8 digits
		 * 
		 * @param password
		 *            the password to set
		 */
		public void setPassword(String password) {
			this.password = password;
		}

		/**
		 * Getter for the CIMI user password repeat attribute
		 * 
		 * @return the passwordRepeat
		 */
		public String getPasswordRepeat() {
			return passwordRepeat;
		}

		/**
		 * Setter for the CIMI user password repeat attribute
		 * 
		 * @param passwordRepeat
		 *            the passwordRepeat to set
		 */
		public void setPasswordRepeat(String passwordRepeat) {
			this.passwordRepeat = passwordRepeat;
		}

		/**
		 * Getter for the CIMI user email address attribute
		 * 
		 * @return the emailAddress
		 */
		public String getEmailAddress() {
			return emailAddress;
		}

		/**
		 * Setter for the CIMI user email address attribute
		 * 
		 * @param emailAddress
		 *            the emailAddress to set
		 */
		public void setEmailAddress(String emailAddress) {
			this.emailAddress = emailAddress;
		}

		/**
		 * Setter for the CIMI user name attribute
		 * 
		 * @param name
		 *            the name to set
		 */
		public void setName(String name) {
			this.name = name;
		}

		/**
		 * Return a {@link java.lang.String <em>String</em>} representation of the
		 * object
		 */
		@Override
		public String toString() {
			return "{" + "href='" + this.href + '\'' + ", username='" + this.name + '\'' + ", password='"
					+ this.password + '\'' + ", password repeat='" + this.passwordRepeat + '\'' + ", email='"
					+ this.emailAddress + '\'' + "}";
		}
	}
}
