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

import java.io.PrintWriter;
import java.util.ArrayList;

import org.joda.time.DateTime;

import com.google.gson.Gson;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.oauth2.AccessTokenResponse;
import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;



public class LastMileJSON implements HttpFilter {

	String encKeyAlias;
	int secondsToLive;
	int secondsScew;
	
	@Override
	public void doFilter(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		chain.setNoProxy(true);
		
		ConfigManager cfgMgr = (ConfigManager) request.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);
		
		PrintWriter out = response.getWriter();
		out.println("<html><head>");
		
		out.println("<script type=\"text/javascript\">");
		out.println("     function onBodyLoad() {");
		out.println("          var element = document.getElementById(\"json\");");
		//out.println("          alert(element.innerHTML);");
		out.println("          window.javascriptAccessor.setJSON(element.innerHTML);");
		out.println("     }");
		out.println("</script></head><body onload=\"onBodyLoad()\">");
		
		out.print("<div id=\"json\">");
		
		DateTime notBefore = new DateTime().minusSeconds(secondsScew);
		DateTime notAfter = new DateTime().plusSeconds(secondsToLive);
		
		AuthController actl = (AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL);
		
		
		
		
		com.tremolosecurity.lastmile.LastMile lmreq = new com.tremolosecurity.lastmile.LastMile(request.getRequestURI(),notBefore,notAfter,1,"chainName");
		lmreq.getAttributes().add(new Attribute("dn",actl.getAuthInfo().getUserDN()));
		
		AccessTokenResponse resp = new AccessTokenResponse();
		resp.setAccess_token(lmreq.generateLastMileToken(cfgMgr.getSecretKey(encKeyAlias)));
		resp.setToken_type("bearer");
		resp.setExpires_in(this.secondsToLive);
		
		Gson gson = new Gson();
		
		out.print(gson.toJson(resp));
		
		out.print("</div></body></html>");

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
		this.encKeyAlias = config.getAttribute("encKeyAlias").getValues().get(0);
		this.secondsToLive = Integer.parseInt(config.getAttribute("secondsToLive").getValues().get(0));
		this.secondsScew = Integer.parseInt(config.getAttribute("secondsScew").getValues().get(0));
	}

}
