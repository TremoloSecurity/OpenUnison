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


package com.tremolosecurity.proxy.auth.otp;

import java.io.IOException;
import java.util.HashMap;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;








import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;

import com.google.gson.Gson;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.AuthMechType;
import com.tremolosecurity.json.Token;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthMechanism;
import com.tremolosecurity.proxy.auth.RequestHolder;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder;


public class OTPAuth implements AuthMechanism {
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(AuthMechanism.class.getName());
	private ConfigManager cfgMgr;
	
	
	
	
	@Override
	public void init(ServletContext ctx, HashMap<String, Attribute> init) {
		this.cfgMgr = (ConfigManager) ctx.getAttribute(ProxyConstants.TREMOLO_CONFIG);
		

	}

	@Override
	public String getFinalURL(HttpServletRequest request,
			HttpServletResponse response) {
		return "";
	}

	@Override
	public void doGet(HttpServletRequest request, HttpServletResponse response,
			AuthStep as) throws IOException, ServletException {
		HttpSession session = ((HttpServletRequest) request).getSession();
		HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
		
		Attribute attr = authParams.get("formURI");
		if (attr == null) {
			throw new ServletException("formURI not present");
		}
		String formURI = attr.getValues().get(0);
		
		request.getRequestDispatcher(formURI).forward(request, response);

	}

	@Override
	public void doPost(HttpServletRequest request,
			HttpServletResponse response, AuthStep as) throws IOException,
			ServletException {
		
		if (request.getParameter("code") == null) {
			this.doGet(request, response, as);
			return;
		}
		
		HttpSession session = ((HttpServletRequest) request).getSession();
		HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		
		RequestHolder reqHolder = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
		
		String urlChain = holder.getUrl().getAuthChain();
		AuthChainType act = holder.getConfig().getAuthChains().get(reqHolder.getAuthChainName());
		AuthMechType amt = act.getAuthMech().get(as.getId());
		
		
		
		Attribute attr = authParams.get("keyName");
		if (attr == null) {
			throw new ServletException("keyName not present");
		}
		
		SecretKey key = this.cfgMgr.getSecretKey(attr.getValues().get(0));
		if (key == null) {
			throw new ServletException("Key '" + attr.getValues().get(0) + "' does not exist");
		}

		int windowSize = 3;
		attr = authParams.get("windowSize");
		if (attr == null) {
			logger.warn("No windowSize set");
		} else {
			windowSize = Integer.parseInt(attr.getValues().get(0));
		}
		
		attr = authParams.get("attributeName");
		if (attr == null) {
			throw new ServletException("attributeName not present");
		}
		
		String attributeName = attr.getValues().get(0);
		
		AuthController ac = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL));
		attr = ac.getAuthInfo().getAttribs().get(attributeName);
		
		if (attr == null) {
			if (logger.isDebugEnabled()) {
				logger.info("Attribute '" + attributeName + "' not present");
			}
			
			as.setSuccess(false);
		} else {
			try {
				String keyjson = attr.getValues().get(0);
				
				if (logger.isDebugEnabled()) {
					logger.debug("token json : '" + keyjson + "'");
				}
				
				Gson gson = new Gson();
				Token token = gson.fromJson(new String(Base64.decode(keyjson)), Token.class);
				byte[] iv = org.bouncycastle.util.encoders.Base64.decode(token.getIv());
				IvParameterSpec spec =  new IvParameterSpec(iv);
			    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
				cipher.init(Cipher.DECRYPT_MODE, key,spec);
				
			    
				byte[] encBytes = org.bouncycastle.util.encoders.Base64.decode(token.getEncryptedRequest());
				String totpJson = new String(cipher.doFinal(encBytes));
				
				TOTPKey totp = gson.fromJson(totpJson, TOTPKey.class);
				
				GoogleAuthenticatorConfigBuilder b = new GoogleAuthenticatorConfigBuilder();
				b.setWindowSize(windowSize);
				
				GoogleAuthenticatorConfig cfg = b.build();
				
				GoogleAuthenticator ga = new GoogleAuthenticator(cfg);
				String code = request.getParameter("code");
				if (code == null) {
					as.setSuccess(false);
				} else {
					as.setSuccess(ga.authorize(totp.getSecretKey(), Integer.parseInt(code)));
				}
				
				String redirectToURL = request.getParameter("target");
				if (redirectToURL != null && ! redirectToURL.isEmpty()) {
					reqHolder.setURL(redirectToURL);
				}
			} catch (Exception e) {
				as.setSuccess(false);
				logger.error("Could not decrypt key",e);
			}
			
			holder.getConfig().getAuthManager().nextAuth(request, response,session,false);
			
		}

	}

	@Override
	public void doPut(HttpServletRequest request, HttpServletResponse response,
			AuthStep as) throws IOException, ServletException {
		this.doGet(request, response, as);

	}

	@Override
	public void doHead(HttpServletRequest request,
			HttpServletResponse response, AuthStep as) throws IOException,
			ServletException {
		this.doGet(request, response, as);

	}

	@Override
	public void doOptions(HttpServletRequest request,
			HttpServletResponse response, AuthStep as) throws IOException,
			ServletException {
		this.doGet(request, response, as);

	}

	@Override
	public void doDelete(HttpServletRequest request,
			HttpServletResponse response, AuthStep as) throws IOException,
			ServletException {
		this.doGet(request, response, as);

	}

}
