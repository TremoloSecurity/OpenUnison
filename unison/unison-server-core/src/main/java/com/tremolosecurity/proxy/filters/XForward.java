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

import java.net.URI;
import java.net.URL;

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;



public class XForward implements HttpFilter {
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(XForward.class.getName());
	boolean createHeaders;
	
	@Override
	public void doFilter(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		
		//URL url = new URL(request.getRequestURL().toString());
		
		URI url = new URI(request.getRequestURL().toString());
		
		String host = request.getHeader("Host").getValues().get(0);
		String proto = url.getScheme();
		String clientIP = request.getRemoteAddr();
		
		if (this.createHeaders) {
			request.addHeader(new Attribute("X-Forwarded-For",clientIP));
			request.addHeader(new Attribute("X-Forwarded-Host",host));
			request.addHeader(new Attribute("X-Forwarded-Proto",proto));
		} else {
			AuthController authCtl = (AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL);
			authCtl.getAuthInfo().getAttribs().put("X-Forwarded-For",new Attribute("X-Forwarded-For", clientIP));
			authCtl.getAuthInfo().getAttribs().put("X-Forwarded-Host",new Attribute("X-Forwarded-Host", host));
			authCtl.getAuthInfo().getAttribs().put("X-Forwarded-Proto",new Attribute("X-Forwarded-Proto", proto));
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
		if (config.getAttribute("createHeaders") != null) {
			this.createHeaders = Boolean.parseBoolean(config.getAttribute("createHeaders").getValues().get(0));
		} else {
			this.createHeaders = false;
		}
		
		logger.info("Create headers : '" + this.createHeaders + "'");

	}

}
