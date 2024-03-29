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

import jakarta.servlet.http.HttpSession;

import com.google.gson.Gson;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;



public class UserToJSON implements HttpFilter {

	boolean doProxy = true;
	
	@Override
	public void doFilter(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		
		
		
		HttpSession session = request.getSession();
		
		AuthController actl = (AuthController) session.getAttribute(ProxyConstants.AUTH_CTL);
		
		
		
		if (actl == null) {
			throw new Exception("No authentication");
		}
		
		
		if (actl.getAuthInfo() != null) {
			AuthInfo authInfo = actl.getAuthInfo();
			
			if (authInfo.getAttribs().containsKey("UserJSON")) {
				authInfo.getAttribs().remove("UserJSON");
			}
		
			Gson gson = new Gson();
			String ret = gson.toJson(authInfo);
			
			
			
			if (doProxy) {
				chain.setNoProxy(false);
				authInfo.getAttribs().put("UserJSON", new Attribute("UserJSON",ret));
				
				chain.nextFilter(request, response, chain);
			} else {
				response.addHeader("UserJSON", ret);
				chain.setNoProxy(true);
			}
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
		//System.out.println("doproxty : " + config.getAttribute("doProxy"));
		this.doProxy = config.getAttribute("doProxy") != null && config.getAttribute("doProxy").getValues().get(0).equalsIgnoreCase("true"); 

	}

}
