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

import java.util.HashMap;

import org.apache.log4j.Logger;

import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;



public class MapUriRoot implements HttpFilter {

	static Logger logger = Logger.getLogger(MapUriRoot.class);
	
	String newRoot;
	String paramName;
	
	
	@Override
	public void doFilter(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		HashMap<String,String> uriParams = (HashMap<String,String>) request.getAttribute("TREMOLO_URI_PARAMS");
		
		String currentUri = (String) uriParams.get("fullURI");
		int endOfRoot = currentUri.indexOf('/',1);
		
		if (endOfRoot < 0) {
			StringBuilder sb = new StringBuilder();
			sb.append(currentUri).append('/');
			response.sendRedirect(sb.toString());
		} else {
			String afterRoot = currentUri.substring(endOfRoot);
			StringBuilder sb = new StringBuilder();
			sb.append(this.newRoot).append(afterRoot);
			uriParams.put(paramName, sb.toString());
			chain.nextFilter(request, response, chain);
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
		this.newRoot = config.getAttribute("newRoot").getValues().get(0);
		this.paramName = config.getAttribute("paramName").getValues().get(0);
	}

}
