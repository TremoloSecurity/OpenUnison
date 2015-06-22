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

import java.util.HashSet;

import org.apache.log4j.Logger;

import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.saml.Attribute;




public class CookieFilter implements HttpFilter {

	static Logger logger = Logger.getLogger(CookieFilter.class.getName());
	
	HashSet<String> toIgnore;
	boolean supportRegex;
	
	@Override
	public void doFilter(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		HashSet<String> toRemove = new HashSet<String>();
		for (String name : request.getCookieNames()) {
			if (this.supportRegex) {
				for (String ignore : this.toIgnore) {
					boolean found = false;
					if (name.matches(ignore)) {
						found = true;
					}
					
					if (! found) {
						toRemove.add(name);
					}
				}
			} else {
				if (! this.toIgnore.contains(name)) {
					toRemove.add(name);
				}
			}
		}

		for (String name : toRemove) {
			request.removeCookie(name);
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
		this.toIgnore = new HashSet<String>();
		Attribute attr = config.getAttribute("ignore");
		if (attr != null) {
			for (String name : attr.getValues()) {
				this.toIgnore.add(name);
				logger.info("Cookie to ignore : '" + name + "'");
			}
		}
		
		attr = config.getAttribute("supportRegex");
		if (attr == null) {
			this.supportRegex = false;
		} else {
			this.supportRegex = attr.getValues().get(0).equalsIgnoreCase("true");
		}
		
		logger.info("Support regular expressions : '" + this.supportRegex + "'");
		
		

	}

	

}
