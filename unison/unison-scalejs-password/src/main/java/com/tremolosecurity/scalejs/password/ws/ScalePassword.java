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
package com.tremolosecurity.scalejs.password.ws;

import java.util.HashMap;
import java.util.List;

import org.apache.logging.log4j.Logger;

import com.google.gson.Gson;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningParams;
import com.tremolosecurity.provisioning.objects.Workflows;
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
import com.tremolosecurity.scalejs.password.cfg.ScalePasswordResetConfig;
import com.tremolosecurity.scalejs.password.data.ScaleJSPasswordRequest;
import com.tremolosecurity.scalejs.password.data.ScalePasswordUser;
import com.tremolosecurity.scalejs.password.sdk.PasswordValidator;
import com.tremolosecurity.scalejs.util.ScaleJSUtils;
import com.tremolosecurity.server.GlobalEntries;


public class ScalePassword implements HttpFilter {
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(ScalePassword.class.getName());
	ScalePasswordResetConfig scaleConfig;
	PasswordValidator validator;
	
	@Override
	public void doFilter(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		Gson gson = new Gson();
		
		
		
		
		
		if (request.getRequestURI().endsWith("/password/config")) {
			response.setContentType("application/json");
			
			
			ScalePasswordUser ssru = new ScalePasswordUser();
			ssru.setConfig(scaleConfig);
			
			AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
			
			Attribute displayNameAttribute = userData.getAttribs().get(this.scaleConfig.getDisplayNameAttribute());
			if (displayNameAttribute != null) {
				ssru.setDisplayName(displayNameAttribute.getValues().get(0));
			} else {
				ssru.setDisplayName("Unknown");
			}
			ScaleJSUtils.addCacheHeaders(response);
			response.getWriter().println(gson.toJson(ssru).trim());
		} else if (request.getMethod().equalsIgnoreCase("POST") && request.getRequestURI().endsWith("/password/submit")) {
			AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
			String json = new String( (byte[]) request.getAttribute(ProxySys.MSG_BODY));
			ScaleJSPasswordRequest sr = gson.fromJson(json, ScaleJSPasswordRequest.class);
			ScaleError errors = new ScaleError();
			
			if (sr.getPassword1() == null || sr.getPassword2() == null) {
				errors.getErrors().add("Passwords are missing");
			} else if (! sr.getPassword1().equals(sr.getPassword2())) {
				errors.getErrors().add("Passwords do not match");
			} else {
				
				List<String> valErrors = this.validator.validate(sr.getPassword1(), userData);
				if (valErrors != null && ! valErrors.isEmpty()) {
					errors.getErrors().addAll(valErrors);
				}
				
				if (errors.getErrors().isEmpty()) {
					ConfigManager cfgMgr = GlobalEntries.getGlobalEntries().getConfigManager();
					WFCall wfCall = new WFCall();
					wfCall.setName(this.scaleConfig.getWorkflowName());
					wfCall.setReason(this.scaleConfig.getReason());
					wfCall.setUidAttributeName(this.scaleConfig.getUidAttribute());
					
					if (this.scaleConfig.isRunSynchronously()) {
						wfCall.getRequestParams().put(ProvisioningParams.UNISON_EXEC_TYPE, ProvisioningParams.UNISON_EXEC_SYNC);
					} else {
						wfCall.getRequestParams().put(ProvisioningParams.UNISON_EXEC_TYPE, ProvisioningParams.UNISON_EXEC_ASYNC);
					}
					
					TremoloUser tu = new TremoloUser();
					tu.setUid(userData.getAttribs().get(this.scaleConfig.getUidAttribute()).getValues().get(0));
					tu.getAttributes().add(new Attribute(this.scaleConfig.getUidAttribute(),userData.getAttribs().get(this.scaleConfig.getUidAttribute()).getValues().get(0)));
					tu.setUserPassword(sr.getPassword1());
					wfCall.setUser(tu);
					
					try {
						com.tremolosecurity.provisioning.workflow.ExecuteWorkflow exec = new com.tremolosecurity.provisioning.workflow.ExecuteWorkflow();
						exec.execute(wfCall, GlobalEntries.getGlobalEntries().getConfigManager());
					} catch (Exception e) {
						logger.error("Could not update user",e);
						if (this.scaleConfig.isRunSynchronously()) {
							errors.getErrors().add("Unable to set your password, make sure it meets with complexity requirements");
						} else {
							errors.getErrors().add("Please contact your system administrator");
						}
					}
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
		this.scaleConfig = new ScalePasswordResetConfig();
		scaleConfig.setDisplayNameAttribute(this.loadAttributeValue("displayNameAttribute", "Display Name Attribute Name", config));
		scaleConfig.getFrontPage().setTitle(this.loadAttributeValue("frontPage.title", "Front Page Title", config));
		scaleConfig.getFrontPage().setText(this.loadAttributeValue("frontPage.text", "Front Page Text", config));
		scaleConfig.setHomeURL(this.loadAttributeValue("homeURL", "Home URL", config));
		scaleConfig.setLogoutURL(this.loadAttributeValue("logoutURL", "Logout URL", config));
		scaleConfig.setUidAttribute(this.loadAttributeValue("uidAttributeName", "UID Attribute Name", config));
		scaleConfig.setReason(this.loadAttributeValue("reason", "Reason Text", config));
		scaleConfig.setWorkflowName(this.loadAttributeValue("workflowName", "Workflow Name", config));
		scaleConfig.setValidatorClassName(this.loadAttributeValue("validatorClassName", "Validator Class", config));
		String val = this.loadOptionalAttributeValue("synchronous", "Run Synchronously", config);
		if (val == null) {
			scaleConfig.setRunSynchronously(false);
		} else {
			scaleConfig.setRunSynchronously(val.equalsIgnoreCase("true"));
		}
		Attribute attr  = config.getAttribute("validator.params");
		scaleConfig.setValidatorParams(new HashMap<String,Attribute>());
		if (attr != null) {
			for (String v : attr.getValues()) {
				String name = v.substring(0,v.indexOf('='));
				String value = v.substring(v.indexOf('=') + 1);
				Attribute param = scaleConfig.getValidatorParams().get(name);
				if (param == null) {
					param = new Attribute(name);
					scaleConfig.getValidatorParams().put(name, param);
				}
				param.getValues().add(value);
				
			}
		}
		
		this.validator = (PasswordValidator) Class.forName(scaleConfig.getValidatorClassName()).newInstance();
		this.validator.init(scaleConfig.getValidatorParams());
		
		

	}

}
