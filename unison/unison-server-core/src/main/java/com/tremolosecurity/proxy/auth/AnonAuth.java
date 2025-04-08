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

import com.tremolosecurity.proxy.TremoloHttpSession;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.AuthMechType;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.util.ProxyConstants;


public class AnonAuth implements AuthMechanism {
	
	

	private String rdn;
	private String uidAttr;
	private String uidVal;
	private ArrayList<Attribute> attrs;

	@Override
	public void doGet(HttpServletRequest request, HttpServletResponse response,AuthStep as)
			throws IOException, ServletException {
		
		setAnonCtx(request, response,as);

	}

	private void setAnonCtx(HttpServletRequest request,
			HttpServletResponse response,AuthStep as) throws ServletException, IOException {
		HttpSession session = request.getSession(); //SharedSession.getSharedSession().getSession(req.getSession().getId());
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		String urlChain = holder.getUrl().getAuthChain();
		AuthChainType act = holder.getConfig().getAuthChains().get(urlChain);
		
		
		
		
		AuthMechType amt = act.getAuthMech().get(as.getId());
		
		
		
		createSession(session, act);
		
		
		as.setSuccess(true);
		
		
		holder.getConfig().getAuthManager().nextAuth(request, response,session,false);
	}

	public void createSession(HttpSession session, AuthChainType act) {
		AuthInfo authInfo = new AuthInfo(this.rdn,(String) session.getAttribute(ProxyConstants.AUTH_MECH_NAME),act.getName(),act.getLevel(), (TremoloHttpSession) session);
		
		
		authInfo.getAttribs().put(this.uidAttr, new Attribute(this.uidAttr,this.uidVal));
		authInfo.getAttribs().put("objectClass", new Attribute("objectClass",GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getUserObjectClass()));
		
		if (this.attrs != null) {
		
			for (Attribute attr : this.attrs) {
				Attribute a = new Attribute(attr.getName());
				a.getValues().addAll(attr.getValues());
				authInfo.getAttribs().put(a.getName(), a);
			}
		
		}
		
		AuthController actl = new AuthController();
		actl.setAuthInfo(authInfo);
		
		session.setAttribute(ProxyConstants.AUTH_CTL, actl);
	}

	@Override
	public void doPost(HttpServletRequest request, HttpServletResponse response,AuthStep as)
			throws IOException, ServletException {
		setAnonCtx(request, response,as);

	}

	@Override
	public void doPut(HttpServletRequest request, HttpServletResponse response,AuthStep as)
			throws IOException, ServletException {
		setAnonCtx(request, response,as);

	}

	@Override
	public void doHead(HttpServletRequest request, HttpServletResponse response,AuthStep as)
			throws IOException, ServletException {
		setAnonCtx(request, response,as);

	}

	@Override
	public void doOptions(HttpServletRequest request,
			HttpServletResponse response,AuthStep as) throws IOException, ServletException {
		
		
		
		setAnonCtx(request, response,as);

	}

	@Override
	public void doDelete(HttpServletRequest request,
			HttpServletResponse response,AuthStep as) throws IOException, ServletException {
		setAnonCtx(request, response,as);

	}

	@Override
	public void init(ServletContext ctx, HashMap<String, Attribute> init) {
		String cfg = init.get("userName").getValues().get(0);
		this.rdn = cfg + "," + GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getLdapRoot();
		this.uidAttr = cfg.substring(0,cfg.indexOf('='));
		this.uidVal =  cfg.substring(cfg.indexOf('=') + 1);
		
		this.attrs = new ArrayList<Attribute>();
		
		for (String paramName : init.keySet()) {
			if (! paramName.equalsIgnoreCase("userName")) {
				this.attrs.add(init.get(paramName));
			}
		}

	}

	@Override
	public String getFinalURL(HttpServletRequest request,
			HttpServletResponse response) {
		return null;
	}

}
