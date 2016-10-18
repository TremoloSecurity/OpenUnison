/*******************************************************************************
 * Copyright 2016 Tremolo Security, Inc.
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
package com.tremolosecurity.unison.proxy.auth.openidconnect;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.logging.log4j.Logger;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;

import com.tremolosecurity.proxy.results.CustomResult;

public class OAuth2BearerTokenResult implements CustomResult {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(OAuth2BearerTokenResult.class);
	
	public String getResultValue(HttpServletRequest request, HttpServletResponse response) throws ServletException {
		StringBuffer b = new StringBuffer();
		
		JsonWebSignature token = (JsonWebSignature) request.getSession().getAttribute("bearerJWS");
		
		if (token == null) {
			return "Bearer NO TOKEN FOUND";
		}
		
		
		
		
		try {
			b.append("Bearer ").append(token.getCompactSerialization());
		} catch (JoseException e) {
			logger.error("Could not serialize token",e);
		}
		
		return b.toString();
		
		
	}

	public void createResultCookie(Cookie cookie, HttpServletRequest request, HttpServletResponse response)
			throws ServletException {
		//Do nothing

	}

}
