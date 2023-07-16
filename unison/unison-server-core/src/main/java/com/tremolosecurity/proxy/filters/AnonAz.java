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


package com.tremolosecurity.proxy.filters;

import jakarta.servlet.http.HttpSession;

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.AuthMechType;
import com.tremolosecurity.proxy.ConfigSys;
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



public class AnonAz implements HttpFilter {
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(AnonAz.class);
	
	private String rdn;
	private String uidAttr;
	private String uidVal;
	
	@Override
	public void doFilter(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		
		HttpSession session = request.getSession(); //SharedSession.getSharedSession().getSession(req.getSession().getId());
		
		AuthController actl = (AuthController) session.getAttribute(ProxyConstants.AUTH_CTL);
		if (actl == null) {
			actl = new AuthController();
			session.setAttribute(ProxyConstants.AUTH_CTL, actl);
		}
		
		
		
		
		if (actl.getAuthInfo() == null) {
			AuthInfo authInfo = new AuthInfo(this.rdn,(String) session.getAttribute(ProxyConstants.AUTH_MECH_NAME),"anonymous",0);
			((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).setAuthInfo(authInfo);
			
			authInfo.getAttribs().put(this.uidAttr, new Attribute(this.uidAttr,this.uidVal));
			authInfo.getAttribs().put("objectClass", new Attribute("objectClass",GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getUserObjectClass()));
			actl.setAuthInfo(authInfo);
			
		}
		
		
		
		chain.nextFilter(request, response, chain);
		

	}

	@Override
	public void filterResponseText(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain,
			StringBuffer data) throws Exception {
		chain.nextFilterResponseText(request, response, chain, data);

	}

	@Override
	public void filterResponseBinary(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain, byte[] data,
			int length) throws Exception {
		chain.nextFilterResponseBinary(request, response, chain, data, length);

	}

	@Override
	public void initFilter(HttpFilterConfig config) throws Exception {
		String cfg = config.getAttribute("userName").getValues().get(0);
		this.rdn = cfg + "," + GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getLdapRoot();
		this.uidAttr = cfg.substring(0,cfg.indexOf('='));
		this.uidVal =  cfg.substring(cfg.indexOf('=') + 1);

	}

}
