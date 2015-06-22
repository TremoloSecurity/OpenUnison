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

import java.io.PrintWriter;
import java.util.Iterator;

import javax.servlet.http.Cookie;









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
	
	@Override
	public void doFilter(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		
		AuthController auth = (AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL);
		
		chain.setNoProxy(true);
		
		response.setContentType("text/html");
		PrintWriter out = response.getWriter();
		
		StringBuffer b = new StringBuffer();
		
		
		b.append("<html><head><title>Tremolo Security ").append("Unison").append(" Login Test</title></head><body><h1>Tremolo Security ").append("Unison").append(" Login Test</h1><table border=\"1\">\n");
		b.append("<tr><td colspan=\"2\"><b>Authentication Data</b></td></tr>\n");
		b.append("<tr><td>Authenticated User DN : </td><td>").append(auth.getAuthInfo().getUserDN()).append("</td></tr>\n");
		b.append("<tr><td>Authentication Level : </td><td>").append(auth.getAuthInfo().getAuthLevel()).append("</td></tr>\n");
		b.append("<tr><td>Authentication Chain : </td><td>").append(auth.getAuthInfo().getAuthMethod()).append("</td></tr>\n");
		b.append("<tr><td colspan=\"2\"><b>Attributes</b></td></tr>\n");
		
		for (String attrName : auth.getAuthInfo().getAttribs().keySet()) {
			Attribute attr = auth.getAuthInfo().getAttribs().get(attrName);
			for (String val : attr.getValues()) {
				b.append("<tr><td>").append(attrName).append("</td><td>").append(val).append("</td></tr>\n");
			}
		}
		
		b.append("<tr><td colspan=\"2\"><b>Headers</b></td></tr>\n");
		
		Iterator<String> it = request.getHeaderNames();
		while (it.hasNext()) {
			String headerName = it.next();
			Attribute header = request.getHeader(headerName);
			for (String val : header.getValues()) {
				b.append("<tr><td>").append(headerName).append("</td><td>").append(val).append("</td></tr>\n");
			}
		}
		
		b.append("<tr><td colspan=\"2\"><b>Cookies</b></td></tr>\n");
		for (String cookieName : request.getCookieNames()) {
			for (Cookie val : request.getCookies(cookieName)) {
				b.append("<tr><td>").append(cookieName).append("</td><td>").append(val.getValue()).append("</td></tr>\n");
			}
		}
		
		b.append("</table>\n");
		
		if (this.logoutURI != null) {
			b.append("Click <a href=\"").append(this.logoutURI).append("\">HERE</a> to logout<br />\n");
		}
		
		b.append("</body></html>\n");
		
		out.print(b.toString());

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

	}

}
