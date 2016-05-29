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

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;

public class RewriteContent implements HttpFilter {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(RewriteContent.class.getName()); 
	
	String search;
	String replace;
	
	@Override
	public void doFilter(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		chain.nextFilter(request, response, chain);

	}

	@Override
	public void filterResponseText(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain,
			StringBuffer data) throws Exception {
		String orig = data.toString();
		int start = orig.indexOf(search);
		logger.info("start : " + start);
		logger.info("search : " + search);
		logger.info(orig);
		int oldstart = 0;
		
		if (start > 0) {
			int len = search.length();
			data.setLength(0);
			while (start > 0) {
				data.append(orig.substring(oldstart,start));
				data.append(this.replace);
				oldstart = start + len;
				start = orig.indexOf(search,oldstart);
			}
			
			data.append(orig.substring(oldstart));
			
		} 
		
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
		this.search = "sp2k7.proxy.demo-enterprise.com";//config.getAttribute("search").getValues().get(0);
		this.replace = "sp2k7.tremolo.lan";//config.getAttribute("replace").getValues().get(0);

	}

}
