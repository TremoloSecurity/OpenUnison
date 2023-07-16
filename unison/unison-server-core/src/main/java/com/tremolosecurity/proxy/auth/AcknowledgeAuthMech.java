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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.apache.logging.log4j.Logger;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.AuthMechType;

import com.tremolosecurity.proxy.TremoloHttpSession;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.myvd.MyVDConnection;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.*;



public class AcknowledgeAuthMech implements AuthMechanism {
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(AcknowledgeAuthMech.class);
	
	public static final String ACK_JSP = "loginJSP";

	private static final String ACK_BANNER = "banner";
	
	ConfigManager cfgMgr;
	
	@Override
	public void doGet(HttpServletRequest req, HttpServletResponse resp,AuthStep as)
			throws ServletException, IOException {
		
		//HttpSession session = SharedSession.getSharedSession().getSession(req.getSession().getId());
		HttpSession session = ((HttpServletRequest) req).getSession();
		HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
		
		String formURI = authParams.get(ACK_JSP).getValues().get(0);
		String banner = authParams.get(ACK_BANNER).getValues().get(0);
		
		req.setAttribute(ACK_BANNER, banner);
		
		req.getRequestDispatcher(formURI).forward(req, resp);
	}

	@Override
	public void doPost(HttpServletRequest req, HttpServletResponse resp,AuthStep as)
			throws ServletException, IOException {
		
		if (req.getParameter("acknowledge") == null) {
			this.doGet(req, resp, as);
			return;
		}
		
		
		HttpSession session = ((HttpServletRequest) req).getSession(); //SharedSession.getSharedSession().getSession(req.getSession().getId());
		UrlHolder holder = (UrlHolder) req.getAttribute(ProxyConstants.AUTOIDM_CFG);
		
		RequestHolder reqHolder = ((AuthController) req.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
		
		HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
		
		
		String urlChain = holder.getUrl().getAuthChain();
		AuthChainType act = holder.getConfig().getAuthChains().get(reqHolder.getAuthChainName());
		
		
		
		
		AuthMechType amt = act.getAuthMech().get(as.getId());
		
		if (req.getParameter("acknowledge") != null && req.getParameter("acknowledge").equalsIgnoreCase("yes")) {
			as.setSuccess(true);
		} else {
			as.setSuccess(false);
		}
		
		
		String redirectToURL = req.getParameter("target");
		if (redirectToURL != null && ! redirectToURL.isEmpty()) {
			reqHolder.setURL(redirectToURL);
		}
		
		holder.getConfig().getAuthManager().nextAuth(req, resp,session,false);
		
		
		
		
		
		
		
		
		
		
	}

	@Override
	public void doPut(HttpServletRequest request, HttpServletResponse response,AuthStep as)
			throws IOException, ServletException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void doHead(HttpServletRequest request, HttpServletResponse response,AuthStep as)
			throws IOException, ServletException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void doOptions(HttpServletRequest request,
			HttpServletResponse response,AuthStep as) throws IOException, ServletException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void doDelete(HttpServletRequest request,
			HttpServletResponse response,AuthStep as) throws IOException, ServletException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void init(ServletContext ctx, HashMap<String, Attribute> init) {
		this.cfgMgr = (ConfigManager) ctx.getAttribute(ProxyConstants.TREMOLO_CONFIG);
		
	}

	@Override
	public String getFinalURL(HttpServletRequest request,
			HttpServletResponse response) {
		// TODO Auto-generated method stub
		return null;
	}

}
