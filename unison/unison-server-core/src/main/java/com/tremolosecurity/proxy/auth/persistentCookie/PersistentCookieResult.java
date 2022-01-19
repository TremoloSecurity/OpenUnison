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

import java.net.URISyntaxException;
import java.util.HashSet;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;
import org.joda.time.DateTime;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.AuthMechType;
import com.tremolosecurity.config.xml.MechanismType;
import com.tremolosecurity.config.xml.ParamType;
import com.tremolosecurity.config.xml.ParamWithValueType;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.sys.AuthManagerImpl;
import com.tremolosecurity.proxy.results.CustomResult;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;

public class PersistentCookieResult implements CustomResult {

	@Override
	public String getResultValue(HttpServletRequest request,
			HttpServletResponse response) throws ServletException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void createResultCookie(Cookie cookie, HttpServletRequest request,
			HttpServletResponse response) throws ServletException {
		
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		ConfigManager mgr = holder.getConfig();
		
		HashSet<String> mechs = new HashSet<String>();
		
		for (String mechName : mgr.getAuthMechs().keySet()) {
			MechanismType mech = mgr.getAuthMechs().get(mechName);
			if (mech.getClassName().equalsIgnoreCase("com.tremolosecurity.proxy.auth.persistentCookie.PersistentCookie")) {
				mechs.add(mechName);
			}
		}
		
		AuthController authCtl = (AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL);
		String chainName = authCtl.getAuthInfo().getAuthChain();
		
		AuthChainType chain = mgr.getAuthChains().get(chainName);
		
		chain = AuthManagerImpl.buildACT(chain, mgr);
		
		int millisToLive = 0;
		String keyAlias = "";
		
		boolean useSSLSession = false;
		
		for (AuthMechType amt : chain.getAuthMech()) {
			if (mechs.contains(amt.getName())) {
				for (ParamWithValueType pt : amt.getParams().getParam()) {
					
					String value = "";
					
					if (pt.getValue() != null && ! pt.getValue().isBlank()) {
						value = pt.getValue();
					} else {
						value = pt.getValueAttribute();
					}
					
					if (pt.getName().equalsIgnoreCase("millisToLive")) {
						millisToLive = Integer.parseInt(value);
					} if (pt.getName().equalsIgnoreCase("useSSLSessionID") && value.equalsIgnoreCase("true")) {
						useSSLSession = true;
					} else if (pt.getName().equalsIgnoreCase("keyAlias")) {
						keyAlias = value;
					}
				}
			}
		}
		
		DateTime now = new DateTime();
		DateTime expires = now.plusMillis(millisToLive);
		
		com.tremolosecurity.lastmile.LastMile lastmile = null;
		
		try {
			lastmile = new com.tremolosecurity.lastmile.LastMile("/",now,expires,0,"NONE");
		} catch (URISyntaxException e) {
			//not possible
		}
		
		lastmile.getAttributes().add(new Attribute("DN",authCtl.getAuthInfo().getUserDN()));
		lastmile.getAttributes().add(new Attribute("CLIENT_IP",request.getRemoteAddr()));
		
		if (useSSLSession) {
			
			Object sessionID = request.getAttribute("javax.servlet.request.ssl_session_id");
			if (sessionID instanceof byte[]) {
				sessionID = new String(Base64.encodeBase64((byte[]) sessionID));
			}
			
			lastmile.getAttributes().add(new Attribute("SSL_SESSION_ID",(String) sessionID));
		}
		
		try {
			cookie.setValue(new StringBuilder().append('"').append(lastmile.generateLastMileToken(mgr.getSecretKey(keyAlias))).append('"').toString());
		} catch (Exception e) {
			throw new ServletException("Could not encrypt persistent cookie",e);
		}
		
		cookie.setMaxAge(millisToLive / 1000);
		
		

	}

	

}
