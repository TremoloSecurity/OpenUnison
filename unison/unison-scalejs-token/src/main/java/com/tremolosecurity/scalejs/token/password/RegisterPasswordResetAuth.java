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
package com.tremolosecurity.scalejs.token.password;

import java.io.IOException;
import java.util.HashMap;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.AuthMechType;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.auth.AuthMechanism;
import com.tremolosecurity.proxy.auth.RequestHolder;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.logout.LogoutUtil;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;

public class RegisterPasswordResetAuth implements AuthMechanism {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(RegisterPasswordResetAuth.class.getName());
	
	String workflowName;
	String uidAttribute;
	
	
	private String loadAttributeValue(String name,String label,HashMap<String, Attribute> config) throws Exception {
		Attribute attr = config.get(name);
		if (attr == null) {
			throw new Exception(label + " not found");
		}
		
		String val = attr.getValues().get(0);
		logger.info(label + ": '" + val + "'");
		
		return val;
	}
	
	@Override
	public void init(ServletContext ctx, HashMap<String, Attribute> init) {
		
		try {
		
			this.workflowName = this.loadAttributeValue("workflowName", "Workflow Name", init);
			this.uidAttribute = this.loadAttributeValue("uidAttributeName", "UID Attribute Name", init);
		} catch (Exception e) {
			logger.error("Could not load auth mech",e);
		}

	}

	@Override
	public String getFinalURL(HttpServletRequest request, HttpServletResponse response) {
		
		return null;
	}

	@Override
	public void doGet(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		
		HttpSession session = ((HttpServletRequest) request).getSession();
		HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		
		RequestHolder reqHolder = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
		
		String urlChain = holder.getUrl().getAuthChain();
		AuthChainType act = holder.getConfig().getAuthChains().get(reqHolder.getAuthChainName());
		AuthMechType amt = act.getAuthMech().get(as.getId());
		
		AuthController ac = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL));
		AuthInfo au = ac.getAuthInfo();
		
		Attribute uid = au.getAttribs().get(this.uidAttribute);
		if (uid  == null) {
			logger.warn("Attribute : '" + this.uidAttribute + "' does not exist");
			as.setSuccess(false);
		} else {
			ResetUserPasswordOnLogout logoutHandler = new ResetUserPasswordOnLogout(this.workflowName,this.uidAttribute,uid.getValues().get(0));
			LogoutUtil.insertFirstLogoutHandler(request, logoutHandler);
			as.setSuccess(true);
		}
		
		holder.getConfig().getAuthManager().nextAuth(request, response,session,false);

	}

	@Override
	public void doPost(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);

	}

	@Override
	public void doPut(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);

	}

	@Override
	public void doHead(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);

	}

	@Override
	public void doOptions(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);

	}

	@Override
	public void doDelete(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);

	}

}
