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
package com.tremolosecurity.proxy.filters;

import java.util.ArrayList;

import javax.crypto.SecretKey;
import javax.servlet.http.Cookie;

import org.apache.logging.log4j.Logger;
import org.joda.time.DateTime;

import com.google.gson.Gson;
import com.tremolosecurity.config.xml.ApplicationType;
import com.tremolosecurity.proxy.ProxyUtil;
import com.tremolosecurity.proxy.SessionManagerImpl;
import com.tremolosecurity.proxy.TremoloHttpSession;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;

public class CheckSession implements HttpFilter {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(CheckSession.class);
	
	String applicationName;
	String cookieName;
	int timeoutSeconds;
	private SecretKey secretKey;
	
	Gson gson;
	
	@Override
	public void doFilter(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		ArrayList<Cookie> sessionCookies = request.getCookies(this.cookieName);
		if (sessionCookies == null || sessionCookies.isEmpty()) {
			response.sendError(401);
		} else {
			for (Cookie cookie : sessionCookies) {
				TremoloHttpSession session = SessionManagerImpl.findSessionFromCookie(cookie, this.secretKey, (SessionManagerImpl) GlobalEntries.getGlobalEntries().get(ProxyConstants.TREMOLO_SESSION_MANAGER));
				if (session == null) {
					response.sendError(401);
				} else {
					AuthInfo userData = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
					if (userData == null || ! userData.isAuthComplete() || userData.getAuthLevel() == 0) {
						response.sendError(401);
					} else {
						SessionInfo si = new SessionInfo();
						if (this.timeoutSeconds > 0) {
							DateTime lastAccessed = (DateTime) session.getAttribute(SessionManagerImpl.TREMOLO_SESSION_LAST_ACCESSED);
							DateTime now = new DateTime();
							DateTime expires = lastAccessed.plusSeconds(this.timeoutSeconds);
							
							si.setMinsLeft((int) ((expires.getMillis() - System.currentTimeMillis()) / 1000 / 60));
						} else {
							si.setMinsLeft(-1);
						}
						
						
						
						String json = gson.toJson(si);
						response.setContentType("application/json");
						response.getWriter().println(json.trim());
						response.sendError(200);
					}
				}
			}
		}
	}

	@Override
	public void filterResponseText(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain,
			StringBuffer data) throws Exception {
		chain.nextFilterResponseText(request, response, chain, data);

	}

	@Override
	public void filterResponseBinary(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain,
			byte[] data, int length) throws Exception {
		chain.nextFilterResponseBinary(request, response, chain, data, length);

	}

	@Override
	public void initFilter(HttpFilterConfig config) throws Exception {
		Attribute attr = config.getAttribute("applicationName");
		if (attr == null) {
			throw new Exception("Application name not set");
		}
		
		this.applicationName = attr.getValues().get(0);
		ApplicationType app = null;
		for (ApplicationType at : config.getConfigManager().getCfg().getApplications().getApplication()) {
			if (at.getName().equalsIgnoreCase(this.applicationName)) {
				app = at;
			}
		}
		
		if (app == null) {
			throw new Exception(this.applicationName + " not found");
		}

		this.cookieName = app.getCookieConfig().getSessionCookieName();
		this.secretKey = config.getConfigManager().getSecretKey(app.getCookieConfig().getKeyAlias());
		this.timeoutSeconds = app.getCookieConfig().getTimeout();
		this.gson = new Gson();
		
	}

}

class SessionInfo {
	int minsLeft;
	
	public SessionInfo() {
		
	}

	public int getMinsLeft() {
		return minsLeft;
	}

	public void setMinsLeft(int minsLeft) {
		this.minsLeft = minsLeft;
	}

	
	
	
}
