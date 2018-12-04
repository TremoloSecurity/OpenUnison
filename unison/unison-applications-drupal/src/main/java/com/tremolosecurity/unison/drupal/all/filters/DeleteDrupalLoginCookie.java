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


package com.tremolosecurity.unison.drupal.all.filters;

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;

public class DeleteDrupalLoginCookie implements HttpFilter {
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(DeleteDrupalLoginCookie.class.getName());
	
	@Override
	public void doFilter(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		if (logger.isDebugEnabled()) {
			logger.debug("In Filter");
		}
		
		if (request.getAuthInfo().getAuthLevel() > 0) {
			if (logger.isDebugEnabled()) {
				logger.debug("Authenticated");
			}
			
			String flag = (String) request.getSession().getAttribute("TREMOLO_DELETE_DRUPAL_FLAG");
			
			if (logger.isDebugEnabled()) {
				logger.debug("Flag : '" + flag + "'");
			}
			if (flag == null) {
				if (logger.isDebugEnabled()) {
					logger.debug("Removing cookie");
				}
				request.removeCookie("http_auth_ext_complete");
				request.getSession().setAttribute("TREMOLO_DELETE_DRUPAL_FLAG", "TREMOLO_DELETE_DRUPAL_FLAG");
			}
		}
		
		if (logger.isDebugEnabled()) {
			logger.debug("Done");
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
		// TODO Auto-generated method stub

	}

	

}
