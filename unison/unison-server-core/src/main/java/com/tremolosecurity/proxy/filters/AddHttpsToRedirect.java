/*******************************************************************************
 * Copyright 2016 Tremolo Security, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package com.tremolosecurity.proxy.filters;

import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.saml.Attribute;

public class AddHttpsToRedirect implements HttpFilter {

	@Override
	public void doFilter(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		chain.nextFilter(request, response, chain);
		
		Attribute redir = response.getHeader("Location");
		if (redir != null) {
			String curVal = redir.getValues().get(0);
			if (curVal.startsWith("http:")) {
				StringBuffer b = new StringBuffer();
				b.append("https").append(curVal.substring(curVal.indexOf(':')));
				redir.getValues().clear();
				redir.getValues().add(b.toString());
			}
		}

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
		// TODO Auto-generated method stub

	}

}
