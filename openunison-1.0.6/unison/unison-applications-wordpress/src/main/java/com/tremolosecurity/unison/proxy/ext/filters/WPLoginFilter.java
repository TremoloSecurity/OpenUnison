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


package com.tremolosecurity.unison.proxy.ext.filters;

import java.net.URLEncoder;

import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.saml.Attribute;

public class WPLoginFilter implements HttpFilter {

	String logoutURI;
	String redirectTo;
	
	public void doFilter(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		
		boolean finishLogout = false;
		
		if (! request.getParameterNames().hasNext()  && request.getQueryStringParams().size() == 0) {
			StringBuffer b = new StringBuffer();
			b.append(request.getRequestURL()).append("?redirect_to=").append(URLEncoder.encode(this.redirectTo, "UTF-8"));
			response.sendRedirect(b.toString());
			chain.setNoProxy(true);
			return;
		} else {
			Attribute action = request.getParameter("action");
			if (action != null) {
				if (action.getValues().get(0).equalsIgnoreCase("logout")) {
					finishLogout = true;
				}
			}
		}
		
		chain.nextFilter(request, response, chain);
		
		if (finishLogout) {
			response.sendRedirect(this.logoutURI);
		}

	}

	public void filterResponseText(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain,
			StringBuffer data) throws Exception {
		// TODO Auto-generated method stub

	}

	public void filterResponseBinary(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain, byte[] data,
			int length) throws Exception {
		// TODO Auto-generated method stub

	}

	public void initFilter(HttpFilterConfig config) throws Exception {
		Attribute attr = config.getAttribute("redirectTo");
		if (attr == null) {
			throw new Exception("redirectTo is required");
		}
		this.redirectTo = attr.getValues().get(0).toString();
		
		attr = config.getAttribute("logout");
		if (attr == null) {
			throw new Exception("logout is required");
		}
		this.logoutURI = attr.getValues().get(0).toString();
		

	}

}
