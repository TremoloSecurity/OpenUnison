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


package com.tremolosecurity.prelude.filters;

import java.io.PrintWriter;
import java.util.Iterator;

import jakarta.servlet.http.Cookie;









import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;



public class LoginTest implements HttpFilter {

	String logoutURI;
	String jspURI;
	
	@Override
	public void doFilter(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		
		request.setAttribute("UNISON_LOGINTEST_LOGOUTURI", this.logoutURI);
		request.getRequestDispatcher(this.jspURI).forward(request.getServletRequest(), response.getServletResponse());

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
		if (config.getAttribute("logoutURI") != null) {
			this.logoutURI = config.getAttribute("logoutURI").getValues().get(0);
		}
		
		if (config.getAttribute("jspURI") != null) {
			this.jspURI = config.getAttribute("jspURI").getValues().get(0);
		} else {
			this.jspURI = "/auth/forms/loginTest.jsp";
		}

	}

}
