/*******************************************************************************
 * Copyright 2016, 2018 Tremolo Security, Inc.
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
package com.tremolosecurity.idp.providers.oidc.session;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

import com.tremolosecurity.idp.providers.OpenIDConnectIdP;
import com.tremolosecurity.idp.providers.oidc.model.OIDCSession;
import com.tremolosecurity.idp.providers.oidc.model.OidcSessionState;
import com.tremolosecurity.proxy.logout.LogoutHandler;

public class ClearOidcSessionOnLogout implements LogoutHandler {

	static Logger logger = Logger.getLogger(ClearOidcSessionOnLogout.class);
	
	OidcSessionState session;
	OpenIDConnectIdP idp;
	
	public ClearOidcSessionOnLogout(OidcSessionState session,OpenIDConnectIdP idp) {
		this.session = session;
		this.idp = idp;
	}
	
	@Override
	public void handleLogout(HttpServletRequest request, HttpServletResponse response) throws ServletException {
		
		try {
			idp.removeAllSessions(session);
		} catch (Exception e) {
			logger.warn(new StringBuilder().append("Could not delete session ").append(session.getSessionID()).toString(),e);
		}
		
	}

}
