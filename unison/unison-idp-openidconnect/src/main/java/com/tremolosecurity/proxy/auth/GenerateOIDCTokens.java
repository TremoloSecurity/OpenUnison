/*******************************************************************************
 * Copyright 2016, 2018 Tremolo Security, Inc.
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
package com.tremolosecurity.proxy.auth;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.apache.logging.log4j.Logger;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.lang.JoseException;

import com.novell.ldap.LDAPException;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.idp.providers.OpenIDConnectIdP;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.auth.util.OpenIDConnectToken;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.proxy.util.ProxyTools;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;

public class GenerateOIDCTokens implements AuthMechanism {

	public static final String UNISON_SESSION_OIDC_ID_TOKEN = "unison.k8s.oidc.idtoken";

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(GenerateOIDCTokens.class.getName());
	
	
	
	

	
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
		
		
		HttpSession session = ((HttpServletRequest) request).getSession(); 
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		if (holder == null) {
			throw new ServletException("Holder is null");
		}
		
		RequestHolder reqHolder = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
		
		HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
		
		AuthController ac = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL));
		
		String idpName = authParams.get("idpName").getValues().get(0);
		String trustName = authParams.get("trustName").getValues().get(0);

		if (authParams.get("doNotTieSession") != null) {
			if (authParams.get("doNotTieSession").getValues().get(0).equals("true")) {
				request.getSession().setAttribute(OpenIDConnectIdP.DO_NOT_TIE_SESSION,OpenIDConnectIdP.DO_NOT_TIE_SESSION);
			}
		} else {
			// make this the default, tieing sessions causes havoc.
			request.getSession().setAttribute(OpenIDConnectIdP.DO_NOT_TIE_SESSION,OpenIDConnectIdP.DO_NOT_TIE_SESSION);
		}

		String overrideURL = request.getRequestURL().toString();
		
		if (authParams.get("overrideURL") != null) {
			overrideURL = authParams.get("overrideURL").getValues().get(0);
		}
		
		
		
		OpenIDConnectToken token = new OpenIDConnectToken(idpName,trustName,overrideURL);
		try {
			request.setAttribute(ProxyTools.OVERRIDE_HOST, System.getProperty("OU_HOST"));
			token.generateToken(request);
		} catch (MalformedClaimException | JoseException | LDAPException | ProvisioningException e) {
			throw new ServletException("Could not generate token",e);
		}
		
		
			
		
		
		
		request.getSession().setAttribute(GenerateOIDCTokens.UNISON_SESSION_OIDC_ID_TOKEN, token);
		
		
		as.setSuccess(true);
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
