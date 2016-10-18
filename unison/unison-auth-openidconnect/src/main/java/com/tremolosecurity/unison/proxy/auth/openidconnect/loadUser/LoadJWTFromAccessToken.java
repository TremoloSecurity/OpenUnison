/*******************************************************************************
 * Copyright 2015, 2016 Tremolo Security, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package com.tremolosecurity.unison.proxy.auth.openidconnect.loadUser;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;
import org.apache.logging.log4j.Logger;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.unison.proxy.auth.openidconnect.sdk.LoadUserData;

public class LoadJWTFromAccessToken implements LoadUserData {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(LoadJWTFromAccessToken.class.getName());
	
	public Map loadUserAttributesFromIdP(HttpServletRequest request, HttpServletResponse response, ConfigManager cfg,
			HashMap<String, Attribute> authParams, Map accessToken) throws Exception {
		
		String tokenName = authParams.get("jwtTokenAttributeName").getValues().get(0);
		
		String hd = authParams.get("hd").getValues().get(0);
		
		//"id_token"
		String jwt = (String) accessToken.get(tokenName);
		
		Map jwtNVP = null;
		
		
		//Since we are getting the token from a valid source, no need to check the signature? (probably not really true, need to figure out what sig to check against)
		int firstPeriod = jwt.indexOf('.');
		int lastPeriod = jwt.lastIndexOf('.');

		String json = new String(Base64.decodeBase64(jwt.substring(firstPeriod + 1,lastPeriod)));
		
		logger.info("json : '" + json + "'");
		
		jwtNVP = com.cedarsoftware.util.io.JsonReader.jsonToMaps(json);

			
		if (hd != null && ! hd.isEmpty()) {
			String emailAddress = (String) jwtNVP.get("email");
			if (emailAddress != null && ! emailAddress.isEmpty()) {
				if (! emailAddress.endsWith(hd)) {
					return null;
				}
			} else {
				return null;
			}
		}
		
		return jwtNVP;
	}

}
