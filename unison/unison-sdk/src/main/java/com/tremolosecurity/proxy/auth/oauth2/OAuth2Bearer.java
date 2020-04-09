/*
Copyright 2015 Tremolo Security, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/


package com.tremolosecurity.proxy.auth.oauth2;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

import javax.crypto.SecretKey;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.AuthMechType;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.auth.AuthMechanism;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;

public abstract class OAuth2Bearer implements AuthMechanism {

	
	private ConfigManager cfgManager;
	
	public ConfigManager getConfigManager() {
		return this.cfgManager;
	}
	
	@Override
	public void init(ServletContext ctx, HashMap<String, Attribute> init) {


	}

	@Override
	public String getFinalURL(HttpServletRequest request,
			HttpServletResponse response) {
		return request.getRequestURL().toString();
	}

	@Override
	public void doGet(HttpServletRequest request, HttpServletResponse response,
			AuthStep as) throws IOException, ServletException {
		
		String basicHdr = request.getHeader("Authorization");
		boolean fromHeader = true;
		
		if (basicHdr == null) {
			basicHdr = request.getParameter("access_token");
			fromHeader = false;
		}
		
		HttpSession session = ((HttpServletRequest) request).getSession();
		HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		String urlChain = holder.getUrl().getAuthChain();
		AuthChainType act = holder.getConfig().getAuthChains().get(urlChain);
		AuthMechType amt = act.getAuthMech().get(as.getId());
		
		
		String realmName = authParams.get("realm").getValues().get(0);
		String scope = null;
		if (authParams.get("scope") != null) {
			scope = authParams.get("scope").getValues().get(0);
		}
		
		
		ConfigManager cfg = (ConfigManager) request.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);
		String accessToken = null;
		
		if (basicHdr == null) {
			as.setExecuted(false);
			sendFail(response, realmName,scope,null,null);
			return;
		} else {
			if (fromHeader) {
				accessToken = basicHdr.substring(basicHdr.indexOf(' ') + 1);
			} else {
				accessToken = basicHdr;
			}
		}
		
		processToken(request, response, as, session, authParams, act,
				realmName, scope, cfg, accessToken);

	}

	public abstract void processToken(HttpServletRequest request,
			HttpServletResponse response, AuthStep as, HttpSession session,
			HashMap<String, Attribute> authParams, AuthChainType act,
			String realmName, String scope, ConfigManager cfg, String lmToken)
			throws ServletException, IOException;

	protected void sendFail(HttpServletResponse response, String realmName, String scope,String error,String errorDesc)
			throws IOException {
		StringBuffer realm = new StringBuffer();
		realm.append("Bearer realm=\"").append(realmName).append('"');
		if (scope != null) {
			realm.append(",scope=\"").append(scope).append("\"");
		}
		
		if (error != null) {
			realm.append(",error=\"").append(error).append("\"");
		}
		
		if (errorDesc != null) {
			realm.append(",error_description=\"").append(errorDesc).append("\"");
		}
		
		response.addHeader("WWW-Authenticate", realm.toString());
		response.sendError(401);
	}
	
	@Override
	public void doPost(HttpServletRequest request,
			HttpServletResponse response, AuthStep as) throws IOException,
			ServletException {
		this.doGet(request, response, as);

	}

	@Override
	public void doPut(HttpServletRequest request, HttpServletResponse response,
			AuthStep as) throws IOException, ServletException {
		this.doGet(request, response, as);

	}

	@Override
	public void doHead(HttpServletRequest request,
			HttpServletResponse response, AuthStep as) throws IOException,
			ServletException {
		this.doGet(request, response, as);

	}

	@Override
	public void doOptions(HttpServletRequest request,
			HttpServletResponse response, AuthStep as) throws IOException,
			ServletException {
		this.doGet(request, response, as);

	}

	@Override
	public void doDelete(HttpServletRequest request,
			HttpServletResponse response, AuthStep as) throws IOException,
			ServletException {
		this.doGet(request, response, as);

	}

	

}
