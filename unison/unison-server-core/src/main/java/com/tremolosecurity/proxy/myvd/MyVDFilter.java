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


package com.tremolosecurity.proxy.myvd;

import static org.apache.directory.ldap.client.api.search.FilterBuilder.equal;

import java.util.ArrayList;

import org.apache.log4j.Logger;

import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;

public class MyVDFilter implements HttpFilter {

	static Logger logger = Logger.getLogger(MyVDFilter.class);
	
	@Override
	public void doFilter(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		
		MyVDConnection con = (MyVDConnection) request.getAttribute(ProxyConstants.AUTOIDM_MYVD);
		String uid = request.getParameter("uid").getValues().get(0);
		String pass = request.getParameter("pwd").getValues().get(0);
		ArrayList<String> attribs = new ArrayList<String>();
		attribs.add("uid");
		
		
		
		LDAPSearchResults res = con.search("o=Tremolo", 2, equal("uid",uid).toString(), attribs);
		res.hasMore();
		LDAPEntry entry = res.next();
		
		String dn = entry.getDN();
		
		boolean bound = false;
		
		try {
			con.bind(dn, pass);
			bound = true;
		} catch (LDAPException e) {
			bound = false;
		}
		
		request.addHeader(new Attribute("userdn",dn));
		request.addHeader(new Attribute("uid",entry.getAttribute("uid").getStringValue()));
		request.addHeader(new Attribute("isauth",Boolean.toString(bound)));
		
		chain.nextFilter(request, response, chain);

	}

	@Override
	public void filterResponseBinary(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain, byte[] data,
			int length) throws Exception {
		chain.nextFilterResponseBinary(request, response, chain, data, length);

	}

	@Override
	public void filterResponseText(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain,
			StringBuffer data) throws Exception {
		chain.nextFilterResponseText(request, response, chain, data);

	}

	@Override
	public void initFilter(HttpFilterConfig config) throws Exception {
		

	}

}
