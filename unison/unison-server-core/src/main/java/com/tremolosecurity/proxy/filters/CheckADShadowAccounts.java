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

import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;



public class CheckADShadowAccounts implements HttpFilter {

	private String nonShadowSuffix;
	private String upnAttributeName;
	private String flagAttributeName;
	private String flagAttributeValue;

	@Override
	public void doFilter(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		
		
		AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
		
		if (! userData.getAttribs().get("userPrincipalName").getValues().get(0).endsWith(this.nonShadowSuffix)) {
			String newUPN = userData.getAttribs().get(this.upnAttributeName).getValues().get(0);
			StringBuffer newUPNVal = new StringBuffer();
			newUPNVal.append(newUPN.replace('@', '.')).append('@').append(this.nonShadowSuffix);
			userData.getAttribs().get("userPrincipalName").getValues().clear();
			userData.getAttribs().get("userPrincipalName").getValues().add(newUPNVal.toString());
			userData.getAttribs().put(this.flagAttributeName, new Attribute(this.flagAttributeName,this.flagAttributeValue));
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
		this.nonShadowSuffix = config.getAttribute("nonShadowSuffix").getValues().get(0);
		this.upnAttributeName = config.getAttribute("upnAttributeName").getValues().get(0);
		this.flagAttributeName = config.getAttribute("flagAttributeName").getValues().get(0);
		this.flagAttributeValue = config.getAttribute("flagAttributeValue").getValues().get(0);
	}

}
