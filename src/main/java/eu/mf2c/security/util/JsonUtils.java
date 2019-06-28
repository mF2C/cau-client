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

import org.apache.log4j.Logger;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Miscellaneous JSON utiltities
 * <p>
 * @author Shirley Crompton
 * @email  shirley.crompton@stfc.ac.uk
 * @org Data Science and Technology Group,
 *      UKRI Science and Technology Council
 * @Created 5 Jun 2019
 */
public class JsonUtils {
	/** Message Logger attribute */
	protected static Logger LOGGER = Logger.getLogger(JsonUtils.class);
	
	/**
	 * Map an object to a JSON String
	 * <p>
	 * @param obj	the object to map
	 * @return		a JSON String representation of the object
	 * @throws JsonProcessingException on mapping errors
	 */
	public static String getJsonStr(Object obj) throws JsonProcessingException {
		ObjectMapper mapper = new ObjectMapper(); //jackson mapper
		String objStr = mapper.writeValueAsString(obj);
		LOGGER.debug("Mapped JSON String : " + objStr);
		return objStr;
	}


}
