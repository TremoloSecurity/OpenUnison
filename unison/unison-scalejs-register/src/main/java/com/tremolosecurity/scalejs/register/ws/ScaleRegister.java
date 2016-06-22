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
package com.tremolosecurity.scalejs.register.ws;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.regex.Matcher;

import org.apache.log4j.Logger;

import com.google.gson.Gson;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.service.util.TremoloUser;
import com.tremolosecurity.provisioning.service.util.WFCall;
import com.tremolosecurity.provisioning.tasks.Approval;
import com.tremolosecurity.provisioning.workflow.ApprovalData;
import com.tremolosecurity.provisioning.workflow.ExecuteWorkflow;
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
import com.tremolosecurity.scalejs.cfg.ScaleAttribute;
import com.tremolosecurity.scalejs.data.ScaleError;
import com.tremolosecurity.scalejs.register.cfg.ScaleJSRegisterConfig;
import com.tremolosecurity.scalejs.register.data.NewUserRequest;
import com.tremolosecurity.server.GlobalEntries;


public class ScaleRegister implements HttpFilter {
	static Logger logger = Logger.getLogger(ScaleRegister.class.getName());
	private ScaleJSRegisterConfig scaleConfig;

	@Override
	public void doFilter(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		Gson gson = new Gson();
		
		if (request.getRequestURI().endsWith("/register/config")) {
			response.setContentType("application/json");
			response.getWriter().println(gson.toJson(scaleConfig).trim());
			
		} else if (request.getRequestURI().endsWith("/register/submit")) {
			ScaleError errors = new ScaleError();
			String json = new String( (byte[]) request.getAttribute(ProxySys.MSG_BODY));
			NewUserRequest newUser = gson.fromJson(json, NewUserRequest.class);
			
			if (this.scaleConfig.isRequireReason() && (newUser.getReason() == null || newUser.getReason().isEmpty())) {
				errors.getErrors().add("Reason is required");
			}
			
			if (this.scaleConfig.isPreSetPassword() ) {
				if (newUser.getPassword() == null || newUser.getPassword().isEmpty()) {
					errors.getErrors().add("Password is required");
				} else if (! newUser.getPassword().equals(newUser.getPassword2())) {
					errors.getErrors().add("Passwords must match");
				}
			}
			
			for (String attributeName : this.scaleConfig.getAttributes().keySet()) {
				String value = newUser.getAttributes().get(attributeName);
				
				if (this.scaleConfig.getAttributes().get(attributeName) == null) {
					errors.getErrors().add("Invalid attribute : '" + attributeName + "'");
					
				} else if (this.scaleConfig.getAttributes().get(attributeName).isReadOnly()) {
					errors.getErrors().add("Attribute is read only : '" + this.scaleConfig.getAttributes().get(attributeName).getDisplayName() + "'");
					
				} else if (this.scaleConfig.getAttributes().get(attributeName).isRequired() && value.length() == 0) {
					errors.getErrors().add("Attribute is required : '" + this.scaleConfig.getAttributes().get(attributeName).getDisplayName() + "'");
					
				} else if (this.scaleConfig.getAttributes().get(attributeName).getMinChars() > 0 && this.scaleConfig.getAttributes().get(attributeName).getMinChars() <= value.length()) {
					errors.getErrors().add(this.scaleConfig.getAttributes().get(attributeName).getDisplayName() + " must have at least " + this.scaleConfig.getAttributes().get(attributeName).getMinChars() + " characters");
					
				} else if (this.scaleConfig.getAttributes().get(attributeName).getMaxChars() > 0 && this.scaleConfig.getAttributes().get(attributeName).getMaxChars() >= value.length()) {
					errors.getErrors().add(this.scaleConfig.getAttributes().get(attributeName).getDisplayName() + " must have at most " + this.scaleConfig.getAttributes().get(attributeName).getMaxChars() + " characters");
					
				} else if (this.scaleConfig.getAttributes().get(attributeName).getPattern() != null) {
					boolean ok = true;
					try {
						Matcher m = this.scaleConfig.getAttributes().get(attributeName).getPattern().matcher(value);
						if (m == null || ! m.matches()) {
							ok = false;
						}
					} catch (Exception e) {
						ok = false;
					}
					
					if (!ok) {
						errors.getErrors().add("Attribute value not valid : '" + this.scaleConfig.getAttributes().get(attributeName).getDisplayName() + "' - " + this.scaleConfig.getAttributes().get(attributeName).getRegExFailedMsg());
					}
				}
			}
			
			
			if (errors.getErrors().isEmpty()) {
				TremoloUser user = new TremoloUser();
				user.setUid(newUser.getAttributes().get(this.scaleConfig.getUidAttributeName()));
				AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
				String uid = userData.getAttribs().get(this.scaleConfig.getUidAttributeName()).getValues().get(0);
				for (String attrName : newUser.getAttributes().keySet()) {
					user.getAttributes().add(new Attribute(attrName,newUser.getAttributes().get(attrName)));	
				}
				
				if (this.scaleConfig.isPreSetPassword()) {
					user.setUserPassword(newUser.getPassword());
					
				}
				
				WFCall wfcall = new WFCall();
				wfcall.setUidAttributeName(this.scaleConfig.getUidAttributeName());
				wfcall.setReason(newUser.getReason());
				wfcall.setName(this.scaleConfig.getWorkflowName());
				wfcall.setUser(user);
				wfcall.setRequestor(userData.getAttribs().get(GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getProvisioning().getApprovalDB().getUserIdAttribute()).getValues().get(0));
				HashMap<String,Object> params = new HashMap<String,Object>();
				wfcall.setRequestParams(params);
				
				
				
				if (scaleConfig.isRequireReason()) {
					
					
					wfcall.getRequestParams().put(Approval.SEND_NOTIFICATION, "false");
					wfcall.getRequestParams().put(Approval.REASON, newUser.getReason());
					wfcall.getRequestParams().put(Approval.IMMEDIATE_ACTION, "true");
					
					
				}
				
				ExecuteWorkflow exec = new ExecuteWorkflow();
				
				try {
					exec.execute(wfcall, GlobalEntries.getGlobalEntries().getConfigManager());
				} catch(Exception e) {
					logger.error("Could register",e);
				}
			} else {
				response.setStatus(500);
				
				response.getWriter().print(gson.toJson(errors).trim());
				response.getWriter().flush();
			}
			
			
		} else {
			response.setStatus(500);
			ScaleError error = new ScaleError();
			error.getErrors().add("Operation not supported");
			response.getWriter().print(gson.toJson(error).trim());
			response.getWriter().flush();
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
		this.scaleConfig = new ScaleJSRegisterConfig();
		scaleConfig.getFrontPage().setTitle(this.loadAttributeValue("frontPage.title", "Front Page Title", config));
		scaleConfig.getFrontPage().setText(this.loadAttributeValue("frontPage.text", "Front Page Text", config));
		scaleConfig.setLogoutURL(this.loadAttributeValue("logoutURL", "Logout URL", config));
		scaleConfig.setUidAttributeName(this.loadAttributeValue("uidAttributeName", "UID Attribute Name", config));
		scaleConfig.setWorkflowName(this.loadAttributeValue("workflowName", "Workflow Name", config));
		
		String val = this.loadOptionalAttributeValue("requireReason", "Require Reason", config);
		scaleConfig.setRequireReason(val != null && val.equals("true"));
		
		val = this.loadOptionalAttributeValue("preSetPassword", "Pre-Set Password", config);
		scaleConfig.setPreSetPassword(val != null && val.equals("true"));
		
		Attribute attr = config.getAttribute("attributeNames");
		if (attr == null) {
			throw new Exception("Attribute names not found");
		}
		
		
		for (String attributeName : attr.getValues()) {
			ScaleAttribute scaleAttr = new ScaleAttribute();
			scaleAttr.setName(attributeName);
			scaleAttr.setDisplayName(this.loadAttributeValue(attributeName + ".displayName", attributeName + " Display Name", config));
			scaleAttr.setReadOnly(false);
			scaleAttr.setRequired(true);
			
			val = this.loadOptionalAttributeValue(attributeName + ".regEx", attributeName + " Reg Ex", config);
			if (val != null) {
				scaleAttr.setRegEx(val);
			}
			
			val = this.loadOptionalAttributeValue(attributeName + ".regExFailedMsg", attributeName + " Reg Ex Failed Message", config);
			if (val != null) {
				scaleAttr.setRegExFailedMsg(val);
			}
			
			val = this.loadOptionalAttributeValue(attributeName + ".minChars", attributeName + " Minimum Characters", config);
			if (val != null) {
				scaleAttr.setMinChars(Integer.parseInt(val));
			}
			
			val = this.loadOptionalAttributeValue(attributeName + ".mxnChars", attributeName + " Maximum Characters", config);
			if (val != null) {
				scaleAttr.setMaxChars(Integer.parseInt(val));
			}
			
			
			scaleConfig.getAttributes().put(attributeName, scaleAttr);
		}
	}

}
