/*
Copyright 2015, 2016 Tremolo Security, Inc.

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


package com.tremolosecurity.proxy.auth;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.AuthMechType;
import com.tremolosecurity.proxy.auth.util.BasicAuthImpl;
import com.tremolosecurity.proxy.auth.util.LDAPBasicAuth;
import com.tremolosecurity.proxy.myvd.MyVDConnection;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;

import com.tremolosecurity.proxy.auth.util.AuthStep;


public class BasicAuth implements AuthMechanism {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(BasicAuth.class.getName());

	ConfigManager cfgMgr;

	private LDAPBasicAuth authImpl;
	
	@Override
	public void doGet(HttpServletRequest request, HttpServletResponse response,AuthStep as)
			throws IOException, ServletException {
		
		
		
		if (checkBasicAuth(request, response,cfgMgr,this.authImpl,as)) {
			
			cfgMgr.getAuthManager().nextAuth(request, response,request.getSession(),false,null);
			
		}
	}

	public static boolean checkBasicAuth(HttpServletRequest request,
			HttpServletResponse response,ConfigManager cfgMgr,BasicAuthImpl authImpl,AuthStep as) throws IOException, ServletException {
		String basicHdr = request.getHeader("Authorization");
		
		HttpSession session = ((HttpServletRequest) request).getSession();
		HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
		String realmName = authParams.get("realmName").getValues().get(0);
		
		String uidAttr = "uid";
		
		if (authParams.get("uidAttr") != null ) {
			uidAttr = authParams.get("uidAttr").getValues().get(0);
		}
		
		
		if (basicHdr == null) {
			as.setExecuted(false);
			sendFail(response, realmName);
			return false;
		}
		
		
		basicHdr = basicHdr.substring(basicHdr.indexOf(' ') + 1);
		String headerVal = new String(Base64.decode(basicHdr));
		
		String userName = headerVal.substring(0,headerVal.indexOf(':'));
		String password = headerVal.substring(headerVal.indexOf(':') + 1);
		
		MyVDConnection myvd = cfgMgr.getMyVD();
		
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		
		
		
		
		String urlChain = holder.getUrl().getAuthChain();
		AuthChainType act = holder.getConfig().getAuthChains().get(urlChain);
		
		
		
		
		AuthMechType amt = act.getAuthMech().get(as.getId());
		
		try {
			authImpl.doAuth(request,session, uidAttr, userName, password, myvd, act, amt,as,cfgMgr);
			
		} catch (LDAPException e) {
			if (e.getResultCode() != LDAPException.INVALID_CREDENTIALS) {
				logger.error("Could not authenticate user",e);
			}
			as.setExecuted(true);
			as.setSuccess(false);
			sendFail(response, realmName);
			return false;
			
			/*if (amt.getRequired().equals("required")) {
				session.setAttribute(AuthSys.AUTH_RES, false);
			}*/
		}
		
		
		
		
		return true;
	}

	

	private static void sendFail(HttpServletResponse response, String realmName)
			throws IOException {
		StringBuffer realm = new StringBuffer();
		realm.append("Basic realm=\"").append(realmName).append('"');
		response.addHeader("WWW-Authenticate", realm.toString());
		response.sendError(401);
	}

	@Override
	public void doPost(HttpServletRequest request, HttpServletResponse response,AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);

	}

	@Override
	public void doPut(HttpServletRequest request, HttpServletResponse response,AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);

	}

	@Override
	public void doHead(HttpServletRequest request, HttpServletResponse response,AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);

	}

	@Override
	public void doOptions(HttpServletRequest request,
			HttpServletResponse response,AuthStep as) throws IOException, ServletException {
		this.doGet(request, response, as);

	}

	@Override
	public void doDelete(HttpServletRequest request,
			HttpServletResponse response,AuthStep as) throws IOException, ServletException {
		this.doGet(request, response, as);

	}

	@Override
	public void init(ServletContext ctx, HashMap<String, Attribute> init) {
		this.cfgMgr = (ConfigManager) ctx.getAttribute(ProxyConstants.TREMOLO_CONFIG);
		this.authImpl = new LDAPBasicAuth();
	}

	@Override
	public String getFinalURL(HttpServletRequest request,
			HttpServletResponse response) {
		
		return null;
	}

}
