/*
Copyright 2015, 2017 Tremolo Security, Inc.

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


package com.tremolosecurity.proxy.auth.persistentCookie;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

import javax.crypto.SecretKey;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.apache.commons.codec.binary.Base64;
import org.apache.logging.log4j.Logger;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.auth.AuthMechanism;
import com.tremolosecurity.proxy.auth.AuthSys;
import com.tremolosecurity.proxy.auth.RequestHolder;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.auth.util.AuthUtil;
import com.tremolosecurity.proxy.myvd.MyVDConnection;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;



public class PersistentCookie implements AuthMechanism {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(PersistentCookie.class);
	
	ConfigManager cfgMgr;
	
	
	@Override
	public void init(ServletContext ctx, HashMap<String, Attribute> init) {
		this.cfgMgr = (ConfigManager) ctx.getAttribute(ProxyConstants.TREMOLO_CONFIG);

	}

	@Override
	public String getFinalURL(HttpServletRequest request,
			HttpServletResponse response) {
		
		return null;
	}

	
	private void doWork(HttpServletRequest request, HttpServletResponse response,
			AuthStep as) throws IOException, ServletException {
		
		as.setExecuted(true);
		
		MyVDConnection myvd = cfgMgr.getMyVD();
		//HttpSession session = (HttpSession) req.getAttribute(ConfigFilter.AUTOIDM_SESSION);//((HttpServletRequest) req).getSession(); //SharedSession.getSharedSession().getSession(req.getSession().getId());
		HttpSession session = ((HttpServletRequest) request).getSession(); //SharedSession.getSharedSession().getSession(req.getSession().getId());
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		
		
		
		if (holder == null) {
			throw new ServletException("Holder is null");
		}
		
		RequestHolder reqHolder = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
		
		String urlChain = holder.getUrl().getAuthChain();
		AuthChainType act = holder.getConfig().getAuthChains().get(reqHolder.getAuthChainName());
		
		HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
		
		Attribute attr = authParams.get("cookieName");
		if (attr == null) {
			throw new ServletException("No cookie name specified");
		}
		
		
		String cookieName = attr.getValues().get(0);
		
		boolean useSSLSessionID;
		attr = authParams.get("useSSLSessionID");
		if (attr == null) {
			useSSLSessionID = false;
		} else {
			useSSLSessionID = attr.getValues().get(0).equalsIgnoreCase("true");
		}
		
		
		
		
		
		attr = authParams.get("millisToLive");
		if (attr == null) {
			throw new ServletException("No milliseconds to live specified");
		}
		
		long millisToLive = Long.parseLong(attr.getValues().get(0));
		
		
		attr = authParams.get("keyAlias");
		if (attr == null) {
			throw new ServletException("No key name specified");
		}
		String keyAlias = attr.getValues().get(0);
		
		Cookie authCookie = null;
		
		if (request.getCookies() == null) {
			as.setSuccess(false);
			holder.getConfig().getAuthManager().nextAuth(request, response,session,false);
			return;
		}
		
		for (Cookie cookie : request.getCookies()) {
			if (cookie.getName().equalsIgnoreCase(cookieName)) {
				authCookie = cookie;
				break;
			}
		}
		
		if (authCookie == null) {
			as.setSuccess(false);
			holder.getConfig().getAuthManager().nextAuth(request, response,session,false);
			return;
		}
		
		com.tremolosecurity.lastmile.LastMile lastmile = new com.tremolosecurity.lastmile.LastMile();
		
		SecretKey key = this.cfgMgr.getSecretKey(keyAlias);
		if (key == null) {
			throw new ServletException("Secret key '" + keyAlias + "' does not exist");
		}
		
		try {
			String cookieVal = authCookie.getValue();
			if (cookieVal.startsWith("\"")) {
				cookieVal = cookieVal.substring(1, cookieVal.length() - 1);
			}
			lastmile.loadLastMielToken(cookieVal, key);
		} catch (Exception e) {
			logger.warn("Could not decrypt cookie",e);
			as.setSuccess(false);
			holder.getConfig().getAuthManager().nextAuth(request, response,session,false);
			return;
		}
		
		if (! lastmile.isValid()) {
			logger.warn("Cookie no longer valid");
			as.setSuccess(false);
			holder.getConfig().getAuthManager().nextAuth(request, response,session,false);
			return;
		}
		
		boolean found = false;
		boolean validip = false;
		boolean validSslSessionId = ! useSSLSessionID;
		String dn = null;
		
		for (Attribute attrib : lastmile.getAttributes()) {
			if (attrib.getName().equalsIgnoreCase("CLIENT_IP")) {
				validip = attrib.getValues().get(0).equals(request.getRemoteAddr());
			} else if (attrib.getName().equalsIgnoreCase("DN")) {
				dn = attrib.getValues().get(0);
				
			} else if (attrib.getName().equalsIgnoreCase("SSL_SESSION_ID")) {
				
				Object sessionID = request.getAttribute("jakarta.servlet.request.ssl_session_id");
				if (sessionID instanceof byte[]) {
					sessionID = new String(Base64.encodeBase64((byte[]) sessionID));
				}
				
				
				validSslSessionId = attrib.getValues().get(0).equals(sessionID);
				
			}
		}
		
		if (dn != null && validip && validSslSessionId) {
			try {
				LDAPSearchResults res = myvd.search(dn, 0, "(objectClass=*)", new ArrayList<String>());
				
				if (res.hasMore()) {
					LDAPEntry entry = res.next();
					while (res.hasMore()) res.next();
					
					Iterator<LDAPAttribute> it = entry.getAttributeSet().iterator();
					AuthInfo authInfo = new AuthInfo(entry.getDN(),(String) session.getAttribute(ProxyConstants.AUTH_MECH_NAME),act.getName(),act.getLevel());
					((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).setAuthInfo(authInfo);
					
					while (it.hasNext()) {
						LDAPAttribute ldapattr = it.next();
						attr = new Attribute(ldapattr.getName());
						String[] vals = ldapattr.getStringValueArray();
						for (int i=0;i<vals.length;i++) {
							attr.getValues().add(vals[i]);
						}
						authInfo.getAttribs().put(attr.getName(), attr);
					}
					
					
					
					as.setSuccess(true);
					
					
					
				} else {
					
					as.setSuccess(false); 
				}
				
			} catch (LDAPException e) {
				if (e.getResultCode() != LDAPException.INVALID_CREDENTIALS) {
					logger.error("Could not authenticate user",e);
				} 
				
				
				as.setSuccess(false);
			}
		} else {
			as.setSuccess(false); 
		}
		
		holder.getConfig().getAuthManager().nextAuth(request, response,session,false);
		
		
		
	}
	
	
	@Override
	public void doGet(HttpServletRequest request, HttpServletResponse response,
			AuthStep as) throws IOException, ServletException {
		doWork(request,response,as);

	}

	@Override
	public void doPost(HttpServletRequest request,
			HttpServletResponse response, AuthStep as) throws IOException,
			ServletException {
		doWork(request,response,as);

	}

	@Override
	public void doPut(HttpServletRequest request, HttpServletResponse response,
			AuthStep as) throws IOException, ServletException {
		doWork(request,response,as);

	}

	@Override
	public void doHead(HttpServletRequest request,
			HttpServletResponse response, AuthStep as) throws IOException,
			ServletException {
		doWork(request,response,as);

	}

	@Override
	public void doOptions(HttpServletRequest request,
			HttpServletResponse response, AuthStep as) throws IOException,
			ServletException {
		doWork(request,response,as);

	}

	@Override
	public void doDelete(HttpServletRequest request,
			HttpServletResponse response, AuthStep as) throws IOException,
			ServletException {
		doWork(request,response,as);

	}



}
