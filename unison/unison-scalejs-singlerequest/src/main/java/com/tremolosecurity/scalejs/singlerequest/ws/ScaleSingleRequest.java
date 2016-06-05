/*******************************************************************************
 * Copyright 2016 Tremolo Security, Inc.
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
package com.tremolosecurity.scalejs.singlerequest.ws;

import java.util.HashMap;

import org.apache.logging.log4j.Logger;

import com.google.gson.Gson;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.service.util.TremoloUser;
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
import com.tremolosecurity.scalejs.data.ScaleError;
import com.tremolosecurity.scalejs.singlerequest.cfg.ScaleSingleRequestConfig;
import com.tremolosecurity.scalejs.singlerequest.data.ScaleSingleRequestUser;
import com.tremolosecurity.scalejs.singlerequest.data.SingleRequest;
import com.tremolosecurity.server.GlobalEntries;


public class ScaleSingleRequest implements HttpFilter {
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(ScaleSingleRequest.class.getName());
	ScaleSingleRequestConfig scaleConfig;
	
	
	@Override
	public void doFilter(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		Gson gson = new Gson();
		
		
		
		
		
		if (request.getRequestURI().endsWith("/singlerequest/config")) {
			response.setContentType("application/json");
			
			
			ScaleSingleRequestUser ssru = new ScaleSingleRequestUser();
			ssru.setConfig(scaleConfig);
			
			AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
			
			Attribute displayNameAttribute = userData.getAttribs().get(this.scaleConfig.getDisplayNameAttribute());
			if (displayNameAttribute != null) {
				ssru.setDisplayName(displayNameAttribute.getValues().get(0));
			} else {
				ssru.setDisplayName("Unknown");
			}
			
			response.getWriter().println(gson.toJson(ssru).trim());
		} else if (request.getMethod().equalsIgnoreCase("POST") && request.getRequestURI().endsWith("/singlerequest/submit")) {
			AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
			String json = new String( (byte[]) request.getAttribute(ProxySys.MSG_BODY));
			SingleRequest sr = gson.fromJson(json, SingleRequest.class);
			ScaleError errors = new ScaleError();
			
			if (sr.getReason() == null || sr.getReason().isEmpty()) {
				errors.getErrors().add("Reason is required");
			} else {
				ConfigManager cfgMgr = GlobalEntries.getGlobalEntries().getConfigManager();
				WFCall wfCall = new WFCall();
				wfCall.setName(this.scaleConfig.getWorkflowName());
				wfCall.setReason(sr.getReason());
				wfCall.setUidAttributeName(this.scaleConfig.getUidAttribute());
				
				TremoloUser tu = new TremoloUser();
				tu.setUid(userData.getAttribs().get(this.scaleConfig.getUidAttribute()).getValues().get(0));
				tu.getAttributes().add(new Attribute(this.scaleConfig.getUidAttribute(),userData.getAttribs().get(this.scaleConfig.getUidAttribute()).getValues().get(0)));
				
				wfCall.setUser(tu);
				
				try {
					com.tremolosecurity.provisioning.workflow.ExecuteWorkflow exec = new com.tremolosecurity.provisioning.workflow.ExecuteWorkflow();
					exec.execute(wfCall, GlobalEntries.getGlobalEntries().getConfigManager());
				} catch (Exception e) {
					logger.error("Could not update user",e);
					errors.getErrors().add("Please contact your system administrator");
				}
			}
			
			
			
			
			if (errors.getErrors().size() > 0) {
				response.setStatus(500);
				
				response.getWriter().print(gson.toJson(errors).trim());
				response.getWriter().flush();
			}
			
			
		}

	}

	@Override
	public void filterResponseText(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain,
			StringBuffer data) throws Exception {
		

	}

	@Override
	public void filterResponseBinary(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain,
			byte[] data, int length) throws Exception {
		

	}

	private String loadAttributeValue(String name,String label,HttpFilterConfig config) throws Exception {
		Attribute attr = config.getAttribute(name);
		if (attr == null) {
			throw new Exception(label + " not found");
		}
		
		String val = attr.getValues().get(0);
		logger.info(label + ": '" + val + "'");
		
		return val;
	}
	
	private String loadOptionalAttributeValue(String name,String label,HttpFilterConfig config) throws Exception {
		Attribute attr = config.getAttribute(name);
		if (attr == null) {
			logger.warn(label + " not found");
			return null;
		}
		
		String val = attr.getValues().get(0);
		logger.info(label + ": '" + val + "'");
		
		return val;
	}
	
	@Override
	public void initFilter(HttpFilterConfig config) throws Exception {
		this.scaleConfig = new ScaleSingleRequestConfig();
		scaleConfig.setDisplayNameAttribute(this.loadAttributeValue("displayNameAttribute", "Display Name Attribute Name", config));
		scaleConfig.getFrontPage().setTitle(this.loadAttributeValue("frontPage.title", "Front Page Title", config));
		scaleConfig.getFrontPage().setText(this.loadAttributeValue("frontPage.text", "Front Page Text", config));
		scaleConfig.setHomeURL(this.loadAttributeValue("homeURL", "Home URL", config));
		scaleConfig.setLogoutURL(this.loadAttributeValue("logoutURL", "Logout URL", config));
		scaleConfig.setWorkflowName(this.loadAttributeValue("workflowName", "Workflow Name", config));
		scaleConfig.setUidAttribute(this.loadAttributeValue("uidAttribute", "UID Attribute", config));
		
		
		
		

	}

}
