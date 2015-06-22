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


package com.tremolosecurity.proxy.filters;

import java.net.URL;
import java.util.HashMap;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.auth.util.HttpBasicAuth;
import com.tremolosecurity.proxy.auth.util.LDAPBasicAuth;
import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;



public class RemoteBasic implements HttpFilter {

	String realmName;
	
	
	ConfigManager cfgMgr;
	
	String url;
	String host;
	int port;
	boolean ssl;
	
	@Override
	public void doFilter(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		
		HashMap<String,Attribute> authParams = new HashMap<String,Attribute>();
		authParams.put("realmName", new Attribute("realmName",this.realmName));
		authParams.put("uidAttr", new Attribute("uidAttr","uid"));
		request.getSession().setAttribute(ProxyConstants.AUTH_MECH_PARAMS, authParams);
		
		AuthStep as = new AuthStep();
		as.setId(0);
		as.setRequired(true);
		
		
		if (com.tremolosecurity.proxy.auth.BasicAuth.checkBasicAuth(request.getServletRequest(), response.getServletResponse(), cfgMgr,new HttpBasicAuth(url, false, host, port),as)) {
			request.removeHeader("Authorization");
			chain.nextFilter(request, response, chain);
		} else {
			chain.setNoProxy(true);
		}

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
		this.realmName = config.getAttribute("realmName").getValues().get(0);
		this.url = config.getAttribute("url").getValues().get(0);
		URL uUrl = new URL(this.url);
		this.host = uUrl.getHost();
		this.ssl = uUrl.getProtocol().equalsIgnoreCase("https");
		this.port = uUrl.getPort();
		if (this.port == 0) {
			if (ssl) {
				this.port = 443;
			} else {
				this.port = 80;
			}
		}

	}

}
