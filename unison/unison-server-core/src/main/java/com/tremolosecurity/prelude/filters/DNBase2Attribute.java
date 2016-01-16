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


package com.tremolosecurity.prelude.filters;

import java.util.ArrayList;

import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;

import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;



public class DNBase2Attribute implements HttpFilter {

	static Logger logger = Logger.getLogger(DNBase2Attribute.class.getName());
	
	String dn;
	String attributeName;
	String attributeValue;
	
	String key;
	
	ConfigManager cfgMgr;

	ArrayList<String> attribs;
	
	@Override
	public void doFilter(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		HttpSession session = request.getSession();
		
		
		if (session.getAttribute(key) == null) {
			AuthInfo authInfo = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
			
			boolean isMember = false;
			
			
			if (authInfo.getUserDN().toLowerCase().endsWith(this.dn)) {
				
				isMember = true;
				logger.debug("User is member");
			} else {
				isMember = false;
				logger.debug("User is NOT member");
			}
			
			if (isMember) {
				Attribute attr = authInfo.getAttribs().get(this.attributeName);
				if (attr == null) {
					attr = new Attribute(this.attributeName);
					authInfo.getAttribs().put(this.attributeName, attr);
				}
				
				attr.getValues().add(this.attributeValue);
			}
			
			session.setAttribute(key, key);
		
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
		this.cfgMgr = config.getConfigManager();
		this.attributeName = config.getAttribute("attributeName").getValues().get(0);
		this.attributeValue = config.getAttribute("attributeValue").getValues().get(0);
		this.dn = config.getAttribute("dn").getValues().get(0).toLowerCase();
		this.attribs = new ArrayList<String>();
		attribs.add("1.1");
		
		StringBuffer b = new StringBuffer();
		b.append("DN2ATTR_").append(this.attributeName).append("_").append(this.attributeValue).append("_").append(this.dn).append("_RUN");
		this.key = b.toString();

	}

}
