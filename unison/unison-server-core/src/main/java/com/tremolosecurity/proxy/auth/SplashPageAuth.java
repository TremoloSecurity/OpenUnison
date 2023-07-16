/*******************************************************************************
 * Copyright (c) 2022 Tremolo Security, Inc.
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

package com.tremolosecurity.proxy.auth;

import java.io.IOException;
import java.util.HashMap;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.AuthMechType;
import com.tremolosecurity.config.xml.MechanismType;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;

public class SplashPageAuth implements AuthMechanism {

	@Override
	public void init(ServletContext ctx, HashMap<String, Attribute> init) {
		

	}

	@Override
	public String getFinalURL(HttpServletRequest request, HttpServletResponse response) {
		
		return null;
	}

	@Override
	public void doGet(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		HttpSession session = ((HttpServletRequest) request).getSession(); // SharedSession.getSharedSession().getSession(req.getSession().getId());
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		String urlChain = holder.getUrl().getAuthChain();
		AuthChainType act = holder.getConfig().getAuthChains().get(urlChain);
		AuthMechType amt = act.getAuthMech().get(as.getId());
		MechanismType mt = GlobalEntries.getGlobalEntries().getConfigManager().getAuthMechs().get(amt.getName());
		HashMap<String, Attribute> authParams = (HashMap<String, Attribute>) session
		.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
		
		if (request.getParameter("finishsso") != null) {
			as.setExecuted(true);
			as.setSuccess(true);
			holder.getConfig().getAuthManager().nextAuth(request, response, session, false);
		} else {
			String redirect = authParams.get("splashUri").getValues().get(0) + "?redirto=" + session.getAttribute("TREMOLO_AUTH_URI");
			response.sendRedirect(redirect);
		}

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
