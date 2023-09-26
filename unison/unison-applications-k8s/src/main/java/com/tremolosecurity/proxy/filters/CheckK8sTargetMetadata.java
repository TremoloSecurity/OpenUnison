/*******************************************************************************
 * Copyright 2020 Tremolo Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package com.tremolosecurity.proxy.filters;

import org.apache.log4j.Logger;
import org.json.simple.JSONObject;

import com.tremolosecurity.proxy.ProxyResponse;
import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;

public class CheckK8sTargetMetadata implements HttpFilter {
	
	static Logger logger = Logger.getLogger(CheckK8sTargetMetadata.class);

	@Override
	public void doFilter(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		
		request.getServletRequest().setAttribute("com.tremolosecurity.unison.proxy.noRedirectOnError", "com.tremolosecurity.unison.proxy.noRedirectOnError");
		
		if (logger.isDebugEnabled()) {
			logger.debug("URI : " + request.getRequestURI());
		}
		
		String name = request.getRequestURI().substring(request.getRequestURI().lastIndexOf('/') + 1);
		
		if (logger.isDebugEnabled()) {
			logger.debug("Looking up for target '" + name + "'");
		}
		
		OpenShiftTarget k8s = (OpenShiftTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(name).getProvider();

		if (logger.isDebugEnabled()) {
			if (k8s == null) {
				logger.debug(name + " not found");
			} else {
				logger.debug(name + " found");
			}
		}
		
		JSONObject root = new JSONObject();
		root.put("isGit", k8s.getGitUrl() != null && ! k8s.getGitUrl().isEmpty());
		
		if (logger.isDebugEnabled()) {
			logger.debug("Response for " + name + " - " + root.toString());
		}
		
		response.setContentType("application/json");
		
		
		
		((ProxyResponse) response.getServletResponse()).pushHeadersAndCookies(null);
		response.getWriter().println(root.toString());
		response.getWriter().flush();
	}

	@Override
	public void filterResponseText(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain,
			StringBuffer data) throws Exception {
		

	}

	@Override
	public void filterResponseBinary(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain,
			byte[] data, int length) throws Exception {
		

	}

	@Override
	public void initFilter(HttpFilterConfig config) throws Exception {
		

	}

}
