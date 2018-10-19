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
package com.tremolosecurity.proxy.results;

import java.net.MalformedURLException;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.lang.JoseException;

import com.novell.ldap.LDAPException;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.proxy.auth.GenerateOIDCTokens;
import com.tremolosecurity.proxy.auth.util.OpenIDConnectToken;
import com.tremolosecurity.proxy.results.CustomResult;

public class InjectIdToken implements CustomResult {

	@Override
	public String getResultValue(HttpServletRequest request, HttpServletResponse response) throws ServletException {
		
		StringBuffer b = new StringBuffer();
		b.append("Bearer ");
		
		OpenIDConnectToken token = (OpenIDConnectToken) request.getSession().getAttribute(GenerateOIDCTokens.UNISON_SESSION_OIDC_ID_TOKEN);
		if (token == null) {
			b.append("NONE");
			
		} else {
			synchronized(token) {
				if (token.isExpired()) {
					try {
						token.refreshProxyToken(request);
					} catch (MalformedURLException | MalformedClaimException | JoseException | LDAPException
							| ProvisioningException e) {
						throw new ServletException("Could not generate id_token",e);
					}
				} 
				
				b.append(token.getEncodedIdJSON());
				
			}
		}
		
		return b.toString();
		
	}

	@Override
	public void createResultCookie(Cookie cookie, HttpServletRequest request, HttpServletResponse response)
			throws ServletException {
		//no cookies

	}

}
