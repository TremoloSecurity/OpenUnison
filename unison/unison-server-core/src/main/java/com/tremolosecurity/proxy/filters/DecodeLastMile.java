/*
Copyright 2020 Tremolo Security, Inc.

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

import javax.crypto.SecretKey;

import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;

public class DecodeLastMile implements HttpFilter {
	
	String keyName;
	String headerName;

	@Override
	public void doFilter(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		SecretKey secret = GlobalEntries.getGlobalEntries().getConfigManager().getSecretKey(this.keyName);
		
		com.tremolosecurity.lastmile.LastMile lm = new com.tremolosecurity.lastmile.LastMile();
		lm.loadLastMielToken(request.getHeader(this.headerName).getValues().get(0), secret);
		if (! lm.isValid()) {
			throw new Exception("Token not valid");
		}
		
		for (Attribute attr : lm.getAttributes()) {
			request.getServletRequest().setAttribute(attr.getName(), attr);
		}
		
		chain.nextFilter(request, response, chain);

	}

	@Override
	public void filterResponseText(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain,
			StringBuffer data) throws Exception {
		// TODO Auto-generated method stub

	}

	@Override
	public void filterResponseBinary(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain,
			byte[] data, int length) throws Exception {
		// TODO Auto-generated method stub

	}

	@Override
	public void initFilter(HttpFilterConfig config) throws Exception {
		
		this.headerName = config.getAttribute("headerName").getValues().get(0);
		this.keyName = config.getAttribute("keyName").getValues().get(0);
	}

}
