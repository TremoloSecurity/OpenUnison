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


package com.tremolosecurity.proxy.auth.oauth2;

import static org.apache.directory.ldap.client.api.search.FilterBuilder.equal;


import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;

import javax.crypto.SecretKey;

import com.novell.ldap.util.ByteArray;
import com.tremolosecurity.proxy.TremoloHttpSession;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.auth.AuthSys;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;



public class OAuth2BearerLastMile extends OAuth2Bearer {

	@Override
	public void processToken(HttpServletRequest request,
			HttpServletResponse response, AuthStep as, HttpSession session,
			HashMap<String, Attribute> authParams, AuthChainType act,
			String realmName, String scope, ConfigManager cfg, String lmToken)
			throws ServletException, IOException {
		
		Attribute attr = authParams.get("lookupByAttribute");
		boolean lookupByAttribute = false;
		if (attr != null) {
			lookupByAttribute = attr.getValues().get(0).equalsIgnoreCase("true");
		}
		
		String lookupAttrName = "";
		if (lookupByAttribute) {
			lookupAttrName = authParams.get("lookupAttributeName").getValues().get(0);
		}
		
		boolean useURIforLastMile = false;
		attr = authParams.get("useURIForLastMile");
		if (attr != null) {
			useURIforLastMile = attr.getValues().get(0).equalsIgnoreCase("true");
		}
		
		
		
		String encKeyAlias = authParams.get("encKeyAlias").getValues().get(0);
		
		SecretKey key = cfg.getSecretKey(encKeyAlias);
		
		com.tremolosecurity.lastmile.LastMile lmresp = new com.tremolosecurity.lastmile.LastMile();
		try {
			lmresp.loadLastMielToken(lmToken, key);
		
			
			StringBuffer uri = new StringBuffer();
			
			
			if (useURIforLastMile) {
				uri.append(request.getRequestURI());
			} else {
				uri.append('/').append(realmName);
				if (scope != null) {
					uri.append('/').append(scope);
				}
			}
			
			
			
			if (! lmresp.isValid(uri.toString())) {
			
				as.setExecuted(true);
				as.setSuccess(false);
				
				cfg.getAuthManager().nextAuth(request, response,request.getSession(),false);
				
				sendFail(response, realmName,scope,"invalid_token","the token is invalid",true,null);
				return;
			}
		} catch (Exception e) {
			throw new ServletException("Invalid token");
		}
		
		String dn = lmresp.getAttributes().get(0).getValues().get(0);
		
		try {
			LDAPSearchResults res;
			if (lookupByAttribute) {
				res = cfg.getMyVD().search(act.getRoot(), 2, equal(lookupAttrName,dn).toString(), new ArrayList<String>());
			} else {
				res = cfg.getMyVD().search(dn, 0, "(objectClass=*)", new ArrayList<String>());
			}
			
			
			
			
			if (res.hasMore()) {
				LDAPEntry entry = res.next();
				while (res.hasMore()) res.next();
				
				Iterator<LDAPAttribute> it = entry.getAttributeSet().iterator();
				AuthInfo authInfo = new AuthInfo(entry.getDN(),(String) session.getAttribute(ProxyConstants.AUTH_MECH_NAME),act.getName(),act.getLevel(),(TremoloHttpSession) session);
				
				AuthController actl = (AuthController) session.getAttribute(ProxyConstants.AUTH_CTL);
				if (actl == null) {
					actl = new AuthController();
					session.setAttribute(ProxyConstants.AUTH_CTL, actl);
				}
				
				actl.setAuthInfo(authInfo);
				
				while (it.hasNext()) {
					LDAPAttribute attrib = it.next();
					attr = new Attribute(attrib.getName());

					LinkedList<ByteArray> vals = attrib.getAllValues();
					for (ByteArray val: vals) {
						attr.getValues().add(new String(val.getValue()));
					}
					authInfo.getAttribs().put(attr.getName(), attr);
				}
				
				
				as.setExecuted(true);
				as.setSuccess(true);
				
				cfg.getAuthManager().nextAuth(request, response,request.getSession(),false);
				
				
				
			} else {
				as.setExecuted(true);
				as.setSuccess(false);
				
				cfg.getAuthManager().nextAuth(request, response,request.getSession(),false);
				
				sendFail(response, realmName,scope,null,null,true,null);
				 
			}
		} catch (LDAPException e) {
			throw new ServletException("Error loading user",e);
		}
	}
}
