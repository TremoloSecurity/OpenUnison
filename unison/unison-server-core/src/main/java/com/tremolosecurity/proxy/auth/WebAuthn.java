/*******************************************************************************
 * Copyright (c) 2021 Tremolo Security, Inc.
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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;
import java.util.zip.InflaterOutputStream;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.google.gson.Gson;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.AuthMechType;
import com.tremolosecurity.provisioning.util.EncryptedMessage;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.auth.webauthn.WebAuthnUserData;
import com.tremolosecurity.proxy.auth.webauthn.WebAuthnUtils;
import com.tremolosecurity.proxy.filters.WebAuthnRegistration;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.util.Base64Util;
import com.webauthn4j.validator.exception.ValidationException;

import edu.emory.mathcs.backport.java.util.Arrays;

public class WebAuthn implements AuthMechanism {
	
	static Logger logger = Logger.getLogger(WebAuthn.class.getName());
	Gson gson;
	SecureRandom random = new SecureRandom();
	
	@Override
	public void init(ServletContext ctx, HashMap<String, Attribute> init) {
		this.gson = new Gson();

	}

	@Override
	public String getFinalURL(HttpServletRequest request, HttpServletResponse response) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void doGet(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		if (request.getParameter("requestOptions") != null && request.getParameter("requestOptions").equalsIgnoreCase("true")) {
			AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
			HttpSession session = ((HttpServletRequest) request).getSession(); //SharedSession.getSharedSession().getSession(req.getSession().getId());
			UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
			RequestHolder reqHolder = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
			String urlChain = holder.getUrl().getAuthChain();
			AuthChainType act = holder.getConfig().getAuthChains().get(reqHolder.getAuthChainName());
			AuthMechType amt = act.getAuthMech().get(as.getId());
			HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
			
			String attributeName = authParams.get("attribute").getValues().get(0);
			String encryptionKeyName = authParams.get("encryptionKeyName").getValues().get(0);
			
			
			if (userData.getAttribs().get(attributeName) == null) {
				StringBuilder sb = new StringBuilder();
				sb.append("User '").append(userData.getUserDN()).append("' does not have attribute '").append(attributeName).append("'");
				logger.warn(sb.toString());
				as.setExecuted(true);
				as.setSuccess(false);
				holder.getConfig().getAuthManager().nextAuth(request, response,session,false);
				return;
				
			}
			
			WebAuthnUserData webauthnUser = WebAuthnUtils.lookupWebAuthnUserData(userData, attributeName, encryptionKeyName);
			
			if (webauthnUser == null) {
				throw new ServletException("No webauthn user data, can not happen");
			}
			
			try {
				
				
				Challenge challenge = new DefaultChallenge();
				
				JSONObject resp = new JSONObject();
				
				JSONObject publicKey = new JSONObject();
				resp.put("publicKey", publicKey);
				
				JSONArray allowedCredentials = new JSONArray();
				publicKey.put("allowedCredentials", allowedCredentials);
				
				
				for (Authenticator auth : webauthnUser.getAuthenticators()) {
					byte[] credentialId = auth.getAttestedCredentialData().getCredentialId();
					
					JSONObject credential = new JSONObject();
					allowedCredentials.add(credential);
					credential.put("type", "public-key");
					credential.put("id", Base64UrlUtil.encodeToString(credentialId));
				}
				
				
				
				
				publicKey.put("challenge", Base64UrlUtil.encodeToString(challenge.getValue()));
				
				publicKey.put("rpId", WebAuthnRegistration.getRpId(request));
				publicKey.put("timeout", 30000);
				publicKey.put("userVerification", authParams.get("userVerificationRequirement").getValues().get(0));
				
				
		        ServerProperty serverProperty = new ServerProperty(new Origin(request.getRequestURL().toString()), WebAuthnRegistration.getRpId(request), challenge, webauthnUser.getId());
				
		        ByteArrayOutputStream bos = new ByteArrayOutputStream();
		        ObjectOutputStream out = null;
		        byte[] yourBytes = null;
		        try {
		          out = new ObjectOutputStream(bos);   
		          out.writeObject(serverProperty);
		          out.flush();
		          yourBytes = bos.toByteArray();
		          
		        } finally {
		          try {
		            bos.close();
		          } catch (IOException ex) {
		            // ignore close exception
		          }
		        }
		        
		        resp.put("serverProperty", java.util.Base64.getUrlEncoder().encodeToString(yourBytes));
		        
		        response.getWriter().println(resp.toString());
				
				
			} catch (Exception e) {
				throw new ServletException(e);
			}
			
			
			
		} else {
			AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
			HttpSession session = ((HttpServletRequest) request).getSession(); //SharedSession.getSharedSession().getSession(req.getSession().getId());
			UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
			RequestHolder reqHolder = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
			String urlChain = holder.getUrl().getAuthChain();
			AuthChainType act = holder.getConfig().getAuthChains().get(reqHolder.getAuthChainName());
			AuthMechType amt = act.getAuthMech().get(as.getId());
			HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
			
			String formURI = authParams.get("formURI").getValues().get(0);
			
			request.getRequestDispatcher(formURI).forward(request, response);
		}

	}

	

	@Override
	public void doPost(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		if (request.getParameter("webauthnResponse") != null) { 
			AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
			HttpSession session = ((HttpServletRequest) request).getSession(); //SharedSession.getSharedSession().getSession(req.getSession().getId());
			UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
			RequestHolder reqHolder = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
			String urlChain = holder.getUrl().getAuthChain();
			AuthChainType act = holder.getConfig().getAuthChains().get(reqHolder.getAuthChainName());
			AuthMechType amt = act.getAuthMech().get(as.getId());
			HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
			
			
			ByteArrayInputStream bais = new ByteArrayInputStream(Base64UrlUtil.decode((String) request.getParameter("serverProperty")));
			ObjectInputStream ois = new ObjectInputStream(bais);
			ServerProperty serverProperty = null;
			try {
				serverProperty = (ServerProperty) ois.readObject();
			} catch (ClassNotFoundException | IOException e) {
				throw new ServletException(e);
			}
			
			String attributeName = authParams.get("attribute").getValues().get(0);
			String encryptionKeyName = authParams.get("encryptionKeyName").getValues().get(0);
			Authenticator auth = null;
			
			if (userData.getAttribs().get(attributeName) == null) {
				StringBuilder sb = new StringBuilder();
				sb.append("User '").append(userData.getUserDN()).append("' does not have attribute '").append(attributeName).append("'");
				logger.warn(sb.toString());
				as.setExecuted(true);
				as.setSuccess(false);
				holder.getConfig().getAuthManager().nextAuth(request, response,session,false);
				return;
				
			}
			
			
			WebAuthnUserData webauthnUser = WebAuthnUtils.lookupWebAuthnUserData(userData, attributeName, encryptionKeyName);
			
			if (webauthnUser == null) {
				throw new ServletException("No webauthn user data, can not happen");
			}

			
			JSONObject webauthnResp = null;
			
			try {
				webauthnResp = (JSONObject) new JSONParser().parse(request.getParameter("webauthnResponse"));
			} catch (ParseException e) {
				throw new ServletException("could not parse webauthn response",e);
			}
			
			
			
			
			byte[] credentialId = java.util.Base64.getUrlDecoder().decode((String) webauthnResp.get("credential_id"));
			byte[] userHandle = java.util.Base64.getUrlDecoder().decode((String) webauthnResp.get("userHandle"));;
			byte[] authenticatorData =  java.util.Base64.getUrlDecoder().decode((String) webauthnResp.get("authenticatorData"));
			byte[] clientDataJSON =  java.util.Base64.getUrlDecoder().decode((String) webauthnResp.get("clientDataJSON"));
			String clientExtensionJSON = (String) webauthnResp.get("clientExtResults");
			byte[] signature =  java.util.Base64.getUrlDecoder().decode((String) webauthnResp.get("signature"));
			
			if (! Arrays.equals(userHandle, webauthnUser.getId())) {
				StringBuilder sb = new StringBuilder();
				sb.append("User '").append(userData.getUserDN()).append("' credential not owned by the client");
				logger.warn(sb.toString());
				as.setExecuted(true);
				as.setSuccess(false);
				holder.getConfig().getAuthManager().nextAuth(request, response,session,false);
				return;
			}
			
			auth = null;
			for (Authenticator checkUser : webauthnUser.getAuthenticators()) {
				if (Arrays.equals(checkUser.getAttestedCredentialData().getCredentialId(), credentialId)) {
					auth = checkUser;
				}
			}
			
			if (auth == null) {
				StringBuilder sb = new StringBuilder();
				sb.append("User '").append(userData.getUserDN()).append("' does not have a credential associated with '").append((String) webauthnResp.get("credential_id")).append("'");
				logger.warn(sb.toString());
				as.setExecuted(true);
				as.setSuccess(false);
				holder.getConfig().getAuthManager().nextAuth(request, response,session,false);
				return;
			}
			
			AuthenticationRequest authenticationRequest =
			        new AuthenticationRequest(
			                credentialId,
			                userHandle,
			                authenticatorData,
			                clientDataJSON,
			                clientExtensionJSON,
			                signature
			        );
			AuthenticationParameters authenticationParameters =
			        new AuthenticationParameters(
			                serverProperty,
			                auth,
			                null,
			                false,
			                true
			        );
			
			WebAuthnManager webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager();
			AuthenticationData authenticationData;
			try {
			    authenticationData = webAuthnManager.parse(authenticationRequest);
			} catch (DataConversionException e) {
				StringBuilder sb = new StringBuilder();
				sb.append("User '").append(userData.getUserDN()).append("' could not parse authentication data with credential '").append((String) webauthnResp.get("credential_id")).append("'");
				logger.warn(sb.toString(),e);
				as.setExecuted(true);
				as.setSuccess(false);
				holder.getConfig().getAuthManager().nextAuth(request, response,session,false);
				return;
			}
			
			try {
			    webAuthnManager.validate(authenticationData, authenticationParameters);
			} catch (ValidationException e) {
				StringBuilder sb = new StringBuilder();
				sb.append("User '").append(userData.getUserDN()).append("' could not validate authentication data with credential '").append((String) webauthnResp.get("credential_id")).append("'");
				logger.warn(sb.toString(),e);
				as.setExecuted(true);
				as.setSuccess(false);
				holder.getConfig().getAuthManager().nextAuth(request, response,session,false);
				return;
			}
			
			as.setExecuted(true);
			as.setSuccess(true);
			holder.getConfig().getAuthManager().nextAuth(request, response,session,false);
			
			
			
		} else {
			// redirect the user to the correct URL
			AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
			HttpSession session = ((HttpServletRequest) request).getSession(); //SharedSession.getSharedSession().getSession(req.getSession().getId());
			UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
			RequestHolder reqHolder = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
			String urlChain = holder.getUrl().getAuthChain();
			AuthChainType act = holder.getConfig().getAuthChains().get(reqHolder.getAuthChainName());
			AuthMechType amt = act.getAuthMech().get(as.getId());
			
			response.sendRedirect(holder.getConfig().getAuthMechs().get(amt.getName()).getUri());
			return;
			
		}

	}

	@Override
	public void doPut(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		// TODO Auto-generated method stub

	}

	@Override
	public void doHead(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		// TODO Auto-generated method stub

	}

	@Override
	public void doOptions(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		// TODO Auto-generated method stub

	}

	@Override
	public void doDelete(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		// TODO Auto-generated method stub

	}
	
	

}
