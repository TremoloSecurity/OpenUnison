/*******************************************************************************
 * Copyright 2017 Tremolo Security, Inc.
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

import java.util.HashSet;
import java.util.Set;

import org.apache.logging.log4j.Logger;

import com.google.gson.Gson;
import com.tremolosecurity.provisioning.service.util.ProvisioningError;
import com.tremolosecurity.provisioning.service.util.ProvisioningResult;
import com.tremolosecurity.provisioning.service.util.WFCall;
import com.tremolosecurity.proxy.ProxySys;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;

public class CallWorkflow implements HttpFilter {
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(CallWorkflow.class.getName());
	Set<String> allowedWorkflows;
	
	
	@Override
	public void doFilter(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
				request.setAttribute("com.tremolosecurity.unison.proxy.noRedirectOnError", "com.tremolosecurity.unison.proxy.noRedirectOnError");
		if (request.getServletRequest().getMethod().equalsIgnoreCase("POST")) {
			AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
			response.setContentType("application/json");
			String json = new String( (byte[]) request.getAttribute(ProxySys.MSG_BODY));
			Gson gson = new Gson();
			WFCall wfCall = gson.fromJson(json.toString(), WFCall.class);
			
			if (! allowedWorkflows.contains(wfCall.getName())) {
				logger.warn(wfCall.getName() + " not authorized");
				response.getServletResponse().sendError(403);
			} else {
				try {
					
					com.tremolosecurity.provisioning.workflow.ExecuteWorkflow exec = new com.tremolosecurity.provisioning.workflow.ExecuteWorkflow();
					exec.execute(wfCall, GlobalEntries.getGlobalEntries().getConfigManager());
				} catch (Throwable t) {
					logger.error("Error executing workflow",t);
					response.getServletResponse().sendError(500);
				}
			}
			
		} else {
			logger.warn("Invalid HTTPS Method : '" + request.getServletRequest().getMethod() + "'");
			response.getServletResponse().sendError(500);
		}

	}

	@Override
	public void filterResponseText(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain,
			StringBuffer data) throws Exception {
		chain.nextFilterResponseText(request, response, chain, data);

	}

	@Override
	public void filterResponseBinary(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain,
			byte[] data, int length) throws Exception {
		chain.nextFilterResponseBinary(request, response, chain, data, length);

	}

	@Override
	public void initFilter(HttpFilterConfig config) throws Exception {
		this.allowedWorkflows = new HashSet<String>();
		Attribute attr = config.getAttribute("allowedWorkflow");
		if (attr == null) {
			logger.warn("No workflows spedified");
		} else {
			this.allowedWorkflows.addAll(attr.getValues());
		}

	}

}
