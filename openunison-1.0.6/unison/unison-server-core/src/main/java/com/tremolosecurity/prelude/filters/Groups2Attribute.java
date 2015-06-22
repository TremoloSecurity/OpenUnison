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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;

import com.novell.ldap.LDAPEntry;
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



public class Groups2Attribute implements HttpFilter {

	static Logger logger = Logger.getLogger(Groups2Attribute.class.getName());
	
	String base;
	String attrName;
	int groupNum;
	Pattern p;
	
	ConfigManager cfg;
	
	String key;
	
	@Override
	public void doFilter(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		
		
		
		HttpSession session = request.getSession();
		
		if (session.getAttribute(key) == null) {
		
			AuthInfo authInfo = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
			
			Attribute members = authInfo.getAttribs().get(this.attrName);
			if (members == null) {
				members = new Attribute();
				authInfo.getAttribs().put(this.attrName, members);
			}
			
			StringBuffer filter = new StringBuffer();
			
			
			
			filter.append("(uniqueMember=").append(authInfo.getUserDN()).append(')');
			
			
			
			ArrayList<String> attrs = new ArrayList<String>();
			attrs.add("cn");
			LDAPSearchResults res = this.cfg.getMyVD().search(this.base, 2, filter.toString(), attrs);
			
			while (res.hasMore()) {
				LDAPEntry entry = res.next();
				String cn = entry.getAttribute("cn").getStringValue();
				
				
				
				
				if (p != null) {
					Matcher m = p.matcher(cn);
					if (m.matches()) {
						
						members.getValues().add(m.group(groupNum));
					}
				} else {
					
					members.getValues().add(cn);
				}
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
		this.cfg = config.getConfigManager();

		
		
		Attribute attr = config.getAttribute("base");
		if (attr == null) {
			throw new Exception("No base specified");
		}
		this.base = attr.getValues().get(0);
		
		attr = config.getAttribute("pattern");
		if (attr != null && ! attr.getValues().get(0).isEmpty()) {
			this.p = Pattern.compile(attr.getValues().get(0));
		} else {
			this.p = null;
		}
		
		attr = config.getAttribute("attrName");
		if (attr == null) {
			throw new Exception("No attribute name specified");
		}
		this.attrName = attr.getValues().get(0);
		
		attr = config.getAttribute("groupNum");
		if (attr != null) {
			this.groupNum = Integer.parseInt(attr.getValues().get(0));
		}
		
		StringBuffer b = new StringBuffer();
		b.append("GS2ATTR_").append(this.attrName).append("_RUN");
		this.key = b.toString();
		
	}



}
