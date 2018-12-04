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


package com.tremolosecurity.proxy.auth;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.AuthMechType;
import com.tremolosecurity.provisioning.util.GenPasswd;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;




public abstract class SMSAuth implements AuthMechanism {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(SMSAuth.class.getName());

	ConfigManager cfgMgr;
	
	@Override
	public void doGet(HttpServletRequest request, HttpServletResponse response,AuthStep as)
			throws IOException, ServletException {
		
		HttpSession session = ((HttpServletRequest) request).getSession();
		HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
		
		
		String from = authParams.get("fromNumber").getValues().get(0);
		String toAttrName = authParams.get("toAttrName").getValues().get(0);
		String redirectForm = authParams.get("redirectForm").getValues().get(0);
		String message = authParams.get("message").getValues().get(0);
		
		
		//Key Options
		if (authParams.get("keyLength") == null) {
			throw new ServletException("Key Length not set");
		}
		
		int keyLen = Integer.parseInt(authParams.get("keyLength").getValues().get(0));
		
		boolean useLowerCase = authParams.get("useLowerCase") != null && authParams.get("useLowerCase").getValues().get(0).equalsIgnoreCase("true");
		boolean useUpperCase = authParams.get("useUpperCase") != null && authParams.get("useUpperCase").getValues().get(0).equalsIgnoreCase("true");
		boolean useNumbers = authParams.get("useNumbers") != null && authParams.get("useNumbers").getValues().get(0).equalsIgnoreCase("true");
		boolean useSpecial = false;//authParams.get("useSpecial") != null && authParams.get("useSpecial").getValues().get(0).equalsIgnoreCase("true");
		
		if (! (useLowerCase || useUpperCase || useNumbers || useSpecial)) {
			throw new ServletException("At least one character type must be chosen");
		}
		
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		
		RequestHolder reqHolder = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
		
		String urlChain = holder.getUrl().getAuthChain();
		AuthChainType act = holder.getConfig().getAuthChains().get(reqHolder.getAuthChainName());
		
		
		AuthMechType amt = act.getAuthMech().get(as.getId());
		
		
		
		
		if (session.getAttribute("TREMOLO_SMS_KEY") == null) {
			GenPasswd gp = new GenPasswd(keyLen,useUpperCase,useLowerCase,useNumbers,useSpecial);
			
			AuthInfo user = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
			String to = user.getAttribs().get(toAttrName).getValues().get(0);
			String key = gp.getPassword();
			
			message = message.replaceAll("[$][{]key[}]", key);
			
			session.setAttribute("TREMOLO_SMS_KEY", key);
			
			sendSMS(authParams, from, message, to);
		}
		
		response.sendRedirect(redirectForm);
		

	}

	

	public abstract void sendSMS(HashMap<String,Attribute> authParams,String from, String message, String to) throws ServletException;



	@Override
	public void doPost(HttpServletRequest request, HttpServletResponse response,AuthStep as)
			throws IOException, ServletException {
		
		HttpSession session = ((HttpServletRequest) request).getSession();
		HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
		
		String keyFromForm = request.getParameter("key");
		
		if (keyFromForm == null) {
			this.doGet(request, response, as);
			return;
		}
		
		String keyFromSession = (String) request.getSession().getAttribute("TREMOLO_SMS_KEY");
		
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		
		RequestHolder reqHolder = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
		
		String urlChain = holder.getUrl().getAuthChain();
		AuthChainType act = holder.getConfig().getAuthChains().get(reqHolder.getAuthChainName());
		
		
		AuthMechType amt = act.getAuthMech().get(as.getId());
		
		boolean authenticated = keyFromForm.equals(keyFromSession);
		
		if (authenticated) {
			session.removeAttribute("TREMOLO_SMS_KEY");
			
		}
		
		as.setSuccess(authenticated);
		
		
		
		
		String redirectToURL = request.getParameter("target");
		if (redirectToURL != null && ! redirectToURL.isEmpty()) {
			reqHolder.setURL(redirectToURL);
		}
		
		holder.getConfig().getAuthManager().nextAuth(request, response,session,authenticated);

	}

	@Override
	public void doPut(HttpServletRequest request, HttpServletResponse response,AuthStep as)
			throws IOException, ServletException {
		throw new ServletException("Operation not supported");

	}

	@Override
	public void doHead(HttpServletRequest request, HttpServletResponse response,AuthStep as)
			throws IOException, ServletException {
		throw new ServletException("Operation not supported");

	}

	@Override
	public void doOptions(HttpServletRequest request,
			HttpServletResponse response,AuthStep as) throws IOException, ServletException {
		throw new ServletException("Operation not supported");

	}

	@Override
	public void doDelete(HttpServletRequest request,
			HttpServletResponse response,AuthStep as) throws IOException, ServletException {
		throw new ServletException("Operation not supported");

	}

	@Override
	public void init(ServletContext ctx, HashMap<String, Attribute> init) {
		this.cfgMgr = (ConfigManager) ctx.getAttribute(ProxyConstants.TREMOLO_CONFIG);
	}

	@Override
	public String getFinalURL(HttpServletRequest request,
			HttpServletResponse response) {
		return null;
	}

}
