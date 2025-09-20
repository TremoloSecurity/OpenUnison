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
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;
import java.util.zip.InflaterOutputStream;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import com.novell.ldap.util.ByteArray;
import com.tremolosecurity.proxy.TremoloHttpSession;
import com.tremolosecurity.proxy.auth.webauthn.ServerPropertyHolder;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.google.gson.Gson;
import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.AuthMechType;
import com.tremolosecurity.provisioning.util.EncryptedMessage;
import com.tremolosecurity.proxy.ProxySys;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.auth.util.AuthUtil;
import com.tremolosecurity.proxy.auth.webauthn.WebAuthnUserData;
import com.tremolosecurity.proxy.auth.webauthn.WebAuthnUtils;
import com.tremolosecurity.proxy.filters.WebAuthnRegistration;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.util.JsonTools;
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

import com.webauthn4j.verifier.exception.VerificationException;

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
		if (request.getParameter("requestOptions") != null
				&& request.getParameter("requestOptions").equalsIgnoreCase("true")) {
			AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL))
					.getAuthInfo();
			HttpSession session = ((HttpServletRequest) request).getSession(); // SharedSession.getSharedSession().getSession(req.getSession().getId());
			UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
			RequestHolder reqHolder = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL))
					.getHolder();
			String urlChain = holder.getUrl().getAuthChain();
			AuthChainType act = holder.getConfig().getAuthChains().get(reqHolder.getAuthChainName());
			AuthMechType amt = act.getAuthMech().get(as.getId());
			HashMap<String, Attribute> authParams = (HashMap<String, Attribute>) session
					.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);

			JSONArray allowedCredentials = null;

			if (userData.getAuthLevel() != 0) {
				// the user is already authenticated, we can generate allowedCredentials
				String attributeName = authParams.get("attribute").getValues().get(0);
				String encryptionKeyName = authParams.get("encryptionKeyName").getValues().get(0);

				if (userData.getAttribs().get(attributeName) == null) {
					StringBuilder sb = new StringBuilder();
					sb.append("User '").append(userData.getUserDN()).append("' does not have attribute '")
							.append(attributeName).append("'");
					logger.warn(sb.toString());
					as.setExecuted(true);
					as.setSuccess(false);
					holder.getConfig().getAuthManager().nextAuth(request, response, session, false);
					return;

				}

				WebAuthnUserData webauthnUser = WebAuthnUtils.lookupWebAuthnUserData(userData, attributeName,
						encryptionKeyName);

				if (webauthnUser == null) {
					throw new ServletException("No webauthn user data, can not happen");
				}

				allowedCredentials = new JSONArray();

				for (Authenticator auth : webauthnUser.getAuthenticators()) {
					byte[] credentialId = auth.getAttestedCredentialData().getCredentialId();

					JSONObject credential = new JSONObject();
					allowedCredentials.add(credential);
					credential.put("type", "public-key");
					credential.put("id", Base64UrlUtil.encodeToString(credentialId));
				}
			}

			try {

				Challenge challenge = new DefaultChallenge();

				JSONObject resp = new JSONObject();

				JSONObject publicKey = new JSONObject();
				resp.put("publicKey", publicKey);

				if (allowedCredentials != null) {
					publicKey.put("allowedCredentials", allowedCredentials);
				}

				publicKey.put("challenge", Base64UrlUtil.encodeToString(challenge.getValue()));

				publicKey.put("rpId", WebAuthnRegistration.getRpId(request));
				publicKey.put("timeout", 30000);
				publicKey.put("userVerification", authParams.get("userVerificationRequirement").getValues().get(0));

				boolean singleStep = authParams.get("singleStep") != null
						&& authParams.get("singleStep").getValues().get(0).equalsIgnoreCase("true");
				
				if (singleStep) {
					resp.put("mediation", "conditional");
				}
				
				
				ServerProperty serverProperty = new ServerProperty(new Origin(request.getRequestURL().toString()),
						WebAuthnRegistration.getRpId(request), challenge, null);
				ServerPropertyHolder serverPropertyHolder = new ServerPropertyHolder();
				serverPropertyHolder.loadFromServerProperty(serverProperty);
				byte[] yourBytes = JsonTools.writeObjectToJson(serverPropertyHolder).getBytes("UTF-8");

				resp.put("serverProperty", java.util.Base64.getUrlEncoder().encodeToString(yourBytes));

				response.getWriter().println(resp.toString());

			} catch (Exception e) {
				throw new ServletException(e);
			}

		} else {
			
			
			
			AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL))
					.getAuthInfo();
			HttpSession session = ((HttpServletRequest) request).getSession(); // SharedSession.getSharedSession().getSession(req.getSession().getId());
			UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
			RequestHolder reqHolder = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL))
					.getHolder();
			String urlChain = holder.getUrl().getAuthChain();
			AuthChainType act = holder.getConfig().getAuthChains().get(reqHolder.getAuthChainName());
			AuthMechType amt = act.getAuthMech().get(as.getId());
			HashMap<String, Attribute> authParams = (HashMap<String, Attribute>) session
					.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);

			String formURI = authParams.get("formURI").getValues().get(0);
			boolean singleStep = authParams.get("singleStep") != null
					&& authParams.get("singleStep").getValues().get(0).equalsIgnoreCase("true");

			boolean allowPassword = authParams.get("allowPassword") != null
					&& authParams.get("allowPassword").getValues().get(0).equalsIgnoreCase("true");

			request.getSession().setAttribute("webauthn.singlestep", singleStep);
			request.getSession().setAttribute("webauthn.allowpassword", allowPassword);

			request.getRequestDispatcher(formURI).forward(request, response);
		}

	}

	@Override
	public void doPost(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		
		if (request.getSession().getAttribute("webauthn.success") != null) {
			request.getSession().removeAttribute("webauthn.success");
			
			HttpSession session = ((HttpServletRequest) request).getSession(); // SharedSession.getSharedSession().getSession(req.getSession().getId());
			UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
			RequestHolder reqHolder = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL))
					.getHolder();
			String urlChain = holder.getUrl().getAuthChain();
			AuthChainType act = holder.getConfig().getAuthChains().get(reqHolder.getAuthChainName());
			AuthMechType amt = act.getAuthMech().get(as.getId());
		
			as.setExecuted(true);
			as.setSuccess(true);
			holder.getConfig().getAuthManager().nextAuth(request, response, session, false);
			return;
		}
		
		
		
		if (request.getContentType().toLowerCase().startsWith("application/json")) {
			
			byte[] requestBytes = (byte[]) request.getAttribute(ProxySys.MSG_BODY);
			String requestString = new String(requestBytes,StandardCharsets.UTF_8);
			JSONObject authResponse = null;
			try {
				 authResponse = (JSONObject) new JSONParser().parse(requestString);
			} catch (ParseException e) {
				throw new ServletException("Could not parse response",e);
			}
			
			JSONObject webauthnResp = null;

			
			webauthnResp = (JSONObject) authResponse.get("webauthnResponse");
			
			
			String jsonServerProperty = new String(Base64UrlUtil.decode((String) authResponse.get("serverProperty")));
			ServerPropertyHolder serverPropertyHolder = (ServerPropertyHolder) JsonTools.readObjectFromJson(jsonServerProperty);
			ServerProperty serverProperty = serverPropertyHolder.getServerProperty();
			
			
			
			
			
			
			
			
			
			
			
			
			byte[] credentialId = java.util.Base64.getUrlDecoder()
					.decode((String) webauthnResp.get("credential_id"));
			byte[] userHandle = java.util.Base64.getUrlDecoder().decode((String) webauthnResp.get("userHandle"));
			;
			byte[] authenticatorData = java.util.Base64.getUrlDecoder()
					.decode((String) webauthnResp.get("authenticatorData"));
			byte[] clientDataJSON = java.util.Base64.getUrlDecoder()
					.decode((String) webauthnResp.get("clientDataJSON"));
			String clientExtensionJSON = (String) webauthnResp.get("clientExtResults");
			byte[] signature = java.util.Base64.getUrlDecoder().decode((String) webauthnResp.get("signature"));
			
			
			AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL))
					.getAuthInfo();
			boolean setNewUserData = false;

			HttpSession session = ((HttpServletRequest) request).getSession(); // SharedSession.getSharedSession().getSession(req.getSession().getId());
			UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
			RequestHolder reqHolder = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL))
					.getHolder();
			String urlChain = holder.getUrl().getAuthChain();
			AuthChainType act = holder.getConfig().getAuthChains().get(reqHolder.getAuthChainName());
			AuthMechType amt = act.getAuthMech().get(as.getId());
			HashMap<String, Attribute> authParams = (HashMap<String, Attribute>) session
					.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
			
			String credentialIdAttributeName = null;
			if (authParams.get("credentialIdAttributeName") == null) {
				logger.warn("No credentialIdAttributeName set, all requests will fail");
				response.sendError(401);
				as.setExecuted(true);
				as.setSuccess(false);
				
				return;
			} else {
				credentialIdAttributeName = authParams.get("credentialIdAttributeName").getValues().get(0);
			}
			
			AuthInfo newUserData = this.findUser((String) webauthnResp.get("credential_id"), credentialIdAttributeName, act, request, holder.getConfig(), (String) session.getAttribute(ProxyConstants.AUTH_MECH_NAME));
			
			if (newUserData == null) {
				logger.warn(String.format("Credential ID %s not found, failing", (String) webauthnResp.get("credential_id")));
				response.sendError(401);
				as.setExecuted(true);
				as.setSuccess(false);
				
				return;
			}
			
			userData = newUserData;
			
			String attributeName = authParams.get("attribute").getValues().get(0);
			String encryptionKeyName = authParams.get("encryptionKeyName").getValues().get(0);
			Authenticator auth = null;

			if (newUserData.getAttribs().get(attributeName) == null) {
				StringBuilder sb = new StringBuilder();
				sb.append("User '").append(newUserData.getUserDN()).append("' does not have attribute '")
						.append(attributeName).append("'");
				logger.warn(sb.toString());
				as.setExecuted(true);
				as.setSuccess(false);
				response.sendError(401);
				return;

			}
			
			

			WebAuthnUserData webauthnUser = WebAuthnUtils.lookupWebAuthnUserData(newUserData, attributeName,
					encryptionKeyName);

			if (webauthnUser == null) {
				throw new ServletException("No webauthn user data, can not happen");
			}
			
			if (!Arrays.equals(userHandle, webauthnUser.getId())) {
				StringBuilder sb = new StringBuilder();
				sb.append("User '").append(userData.getUserDN()).append("' credential not owned by the client");
				logger.warn(sb.toString());
				as.setExecuted(true);
				as.setSuccess(false);
				holder.getConfig().getAuthManager().nextAuth(request, response, session, false);
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
				sb.append("User '").append(userData.getUserDN())
						.append("' does not have a credential associated with '")
						.append((String) webauthnResp.get("credential_id")).append("'");
				logger.warn(sb.toString());
				as.setExecuted(true);
				as.setSuccess(false);
				holder.getConfig().getAuthManager().nextAuth(request, response, session, false);
				return;
			}

			
			
			AuthenticationRequest authenticationRequest = new AuthenticationRequest(credentialId, userHandle,
					authenticatorData, clientDataJSON, clientExtensionJSON, signature);
			AuthenticationParameters authenticationParameters = new AuthenticationParameters(serverProperty, auth,
					null, false, true);

			WebAuthnManager webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager();
			AuthenticationData authenticationData;
			try {
				authenticationData = webAuthnManager.parse(authenticationRequest);
			} catch (DataConversionException e) {
				StringBuilder sb = new StringBuilder();
				sb.append("User '").append(userData.getUserDN())
						.append("' could not parse authentication data with credential '")
						.append((String) webauthnResp.get("credential_id")).append("'");
				logger.warn(sb.toString(), e);
				as.setExecuted(true);
				as.setSuccess(false);
				holder.getConfig().getAuthManager().nextAuth(request, response, session, false);
				return;
			}

			try {
				webAuthnManager.verify(authenticationData, authenticationParameters);
			} catch (VerificationException e) {
				StringBuilder sb = new StringBuilder();
				sb.append("User '").append(userData.getUserDN())
						.append("' could not validate authentication data with credential '")
						.append((String) webauthnResp.get("credential_id")).append("'");
				logger.warn(sb.toString(), e);
				as.setExecuted(true);
				as.setSuccess(false);
				holder.getConfig().getAuthManager().nextAuth(request, response, session, false);
				return;
			}

			if (setNewUserData) {
				((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).setAuthInfo(userData);
			}
			
			String uidAttr = "uid";
			if (authParams.get("uidAttr") != null) {
				uidAttr = authParams.get("uidAttr").getValues().get(0);
			}

			String workflowName = "";
			if (authParams.get("workflowName") != null) {
				workflowName = authParams.get("workflowName").getValues().get(0);
			} else {
				throw new ServletException("workflowName not set");
			}
			
			try {
				WebAuthnUtils.storeWebAuthnUserData(webauthnUser, encryptionKeyName, userData, workflowName,
						uidAttr, attributeName);
			} catch (Exception e) {
				throw new ServletException("Could not store authentication data", e);
			}
			
			
			((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).setAuthInfo(userData);
			
			session.setAttribute("webauthn.success", "success");
			
		} else if (request.getParameter("webauthnResponse") != null) {

			twoFaPost(request, response, as);

		} else {
			// redirect the user to the correct URL
			AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL))
					.getAuthInfo();
			HttpSession session = ((HttpServletRequest) request).getSession(); // SharedSession.getSharedSession().getSession(req.getSession().getId());
			UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
			RequestHolder reqHolder = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL))
					.getHolder();
			String urlChain = holder.getUrl().getAuthChain();
			AuthChainType act = holder.getConfig().getAuthChains().get(reqHolder.getAuthChainName());
			AuthMechType amt = act.getAuthMech().get(as.getId());

			holder.getConfig().getContextPath();

			StringBuilder redirecturi = new StringBuilder();
			redirecturi.append(holder.getConfig().getContextPath())
					.append(holder.getConfig().getAuthMechs().get(amt.getName()).getUri());

			response.sendRedirect(redirecturi.toString());
			return;

		}

	}

	private void twoFaPost(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws ServletException, IOException {
		AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL))
				.getAuthInfo();
		boolean setNewUserData = false;

		HttpSession session = ((HttpServletRequest) request).getSession(); // SharedSession.getSharedSession().getSession(req.getSession().getId());
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		RequestHolder reqHolder = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL))
				.getHolder();
		String urlChain = holder.getUrl().getAuthChain();
		AuthChainType act = holder.getConfig().getAuthChains().get(reqHolder.getAuthChainName());
		AuthMechType amt = act.getAuthMech().get(as.getId());
		HashMap<String, Attribute> authParams = (HashMap<String, Attribute>) session
				.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);

		String uidAttr = "uid";
		if (authParams.get("uidAttr") != null) {
			uidAttr = authParams.get("uidAttr").getValues().get(0);
		}

		String workflowName = "";
		if (authParams.get("workflowName") != null) {
			workflowName = authParams.get("workflowName").getValues().get(0);
		} else {
			throw new ServletException("workflowName not set");
		}

		if (userData.getAuthLevel() == 0) {
			String userName = request.getParameter("username");

			boolean uidIsFilter = false;
			if (authParams.get("uidIsFilter") != null) {
				uidIsFilter = authParams.get("uidIsFilter").getValues().get(0).equalsIgnoreCase("true");
			}

			AuthInfo newAuthInfo = this.findUser(userName, uidIsFilter, uidAttr, act, request, holder.getConfig(),
					(String) session.getAttribute(ProxyConstants.AUTH_MECH_NAME));
			if (newAuthInfo == null) {
				logger.warn(String.format("User %s does not exist", userName));
				as.setExecuted(true);
				as.setSuccess(false);
				holder.getConfig().getAuthManager().nextAuth(request, response, session, false);
				return;
			} else {
				setNewUserData = true;
				userData = newAuthInfo;
			}

		}

		boolean allowPassword = authParams.get("allowPassword") != null
				&& authParams.get("allowPassword").getValues().get(0).equalsIgnoreCase("true");

		if (request.getParameter("webauthnResponse").isBlank()) {
			if (allowPassword) {
				String password = request.getParameter("password");
				if (password == null || password.isBlank()) {
					logger.warn(String.format("No password for %s specified", userData.getUserDN()));
					as.setExecuted(true);
					as.setSuccess(false);
					holder.getConfig().getAuthManager().nextAuth(request, response, session, false);
					return;
				} else {
					try {
						holder.getConfig().getMyVD().bind(userData.getUserDN(), password);
						if (setNewUserData) {
							((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).setAuthInfo(userData);
						}

						as.setExecuted(true);
						as.setSuccess(true);
						holder.getConfig().getAuthManager().nextAuth(request, response, session, false);
						return;
					} catch (LDAPException e) {
						if (e.getResultCode() != LDAPException.INVALID_CREDENTIALS) {
							throw new ServletException("Could not perform legacy authentication", e);
						} else {
							as.setExecuted(true);
							as.setSuccess(false);
							holder.getConfig().getAuthManager().nextAuth(request, response, session, false);
							return;
						}

					}
				}
			} else {
				logger.warn(String.format("No webauthnResponse parameter, failing"));
				as.setExecuted(true);
				as.setSuccess(false);
				holder.getConfig().getAuthManager().nextAuth(request, response, session, false);
				return;
			}
		} else {

			
			
		
			ServerPropertyHolder serverPropertyHolder = (ServerPropertyHolder) JsonTools.readObjectFromJson(new String(Base64UrlUtil.decode((String) request.getParameter("serverProperty"))));
			ServerProperty serverProperty = serverPropertyHolder.getServerProperty();
			

			String attributeName = authParams.get("attribute").getValues().get(0);
			String encryptionKeyName = authParams.get("encryptionKeyName").getValues().get(0);
			Authenticator auth = null;

			if (userData.getAttribs().get(attributeName) == null) {
				StringBuilder sb = new StringBuilder();
				sb.append("User '").append(userData.getUserDN()).append("' does not have attribute '")
						.append(attributeName).append("'");
				logger.warn(sb.toString());
				as.setExecuted(true);
				as.setSuccess(false);
				holder.getConfig().getAuthManager().nextAuth(request, response, session, false);
				return;

			}

			WebAuthnUserData webauthnUser = WebAuthnUtils.lookupWebAuthnUserData(userData, attributeName,
					encryptionKeyName);

			if (webauthnUser == null) {
				throw new ServletException("No webauthn user data, can not happen");
			}

			JSONObject webauthnResp = null;

			try {
				webauthnResp = (JSONObject) new JSONParser().parse(request.getParameter("webauthnResponse"));
			} catch (ParseException e) {
				throw new ServletException("could not parse webauthn response", e);
			}

			byte[] credentialId = java.util.Base64.getUrlDecoder()
					.decode((String) webauthnResp.get("credential_id"));
			byte[] userHandle = java.util.Base64.getUrlDecoder().decode((String) webauthnResp.get("userHandle"));
			;
			byte[] authenticatorData = java.util.Base64.getUrlDecoder()
					.decode((String) webauthnResp.get("authenticatorData"));
			byte[] clientDataJSON = java.util.Base64.getUrlDecoder()
					.decode((String) webauthnResp.get("clientDataJSON"));
			String clientExtensionJSON = (String) webauthnResp.get("clientExtResults");
			byte[] signature = java.util.Base64.getUrlDecoder().decode((String) webauthnResp.get("signature"));

			if (!Arrays.equals(userHandle, webauthnUser.getId())) {
				StringBuilder sb = new StringBuilder();
				sb.append("User '").append(userData.getUserDN()).append("' credential not owned by the client");
				logger.warn(sb.toString());
				as.setExecuted(true);
				as.setSuccess(false);
				holder.getConfig().getAuthManager().nextAuth(request, response, session, false);
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
				sb.append("User '").append(userData.getUserDN())
						.append("' does not have a credential associated with '")
						.append((String) webauthnResp.get("credential_id")).append("'");
				logger.warn(sb.toString());
				as.setExecuted(true);
				as.setSuccess(false);
				holder.getConfig().getAuthManager().nextAuth(request, response, session, false);
				return;
			}

			AuthenticationRequest authenticationRequest = new AuthenticationRequest(credentialId, userHandle,
					authenticatorData, clientDataJSON, clientExtensionJSON, signature);
			AuthenticationParameters authenticationParameters = new AuthenticationParameters(serverProperty, auth,
					null, false, true);

			WebAuthnManager webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager();
			AuthenticationData authenticationData;
			try {
				authenticationData = webAuthnManager.parse(authenticationRequest);
			} catch (DataConversionException e) {
				StringBuilder sb = new StringBuilder();
				sb.append("User '").append(userData.getUserDN())
						.append("' could not parse authentication data with credential '")
						.append((String) webauthnResp.get("credential_id")).append("'");
				logger.warn(sb.toString(), e);
				as.setExecuted(true);
				as.setSuccess(false);
				holder.getConfig().getAuthManager().nextAuth(request, response, session, false);
				return;
			}

			try {
				webAuthnManager.verify(authenticationData, authenticationParameters);
			} catch (VerificationException e) {
				StringBuilder sb = new StringBuilder();
				sb.append("User '").append(userData.getUserDN())
						.append("' could not validate authentication data with credential '")
						.append((String) webauthnResp.get("credential_id")).append("'");
				logger.warn(sb.toString(), e);
				as.setExecuted(true);
				as.setSuccess(false);
				holder.getConfig().getAuthManager().nextAuth(request, response, session, false);
				return;
			}

			if (setNewUserData) {
				((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).setAuthInfo(userData);
			}

			try {
				WebAuthnUtils.storeWebAuthnUserData(webauthnUser, encryptionKeyName, userData, workflowName,
						uidAttr, attributeName);
			} catch (Exception e) {
				throw new ServletException("Could not store authentication data", e);
			}

			as.setExecuted(true);
			as.setSuccess(true);
			holder.getConfig().getAuthManager().nextAuth(request, response, session, false);
		}
	}

	private AuthInfo findUser(String username, boolean uidIsFilter, String uidAttr, AuthChainType act,
			HttpServletRequest req, ConfigManager cfgMgr, String authMechName) {
		String filter = "";
		if (uidIsFilter) {
			StringBuffer b = new StringBuffer();
			int lastIndex = 0;
			int index = uidAttr.indexOf('$');
			while (index >= 0) {
				b.append(uidAttr.substring(lastIndex, index));
				lastIndex = uidAttr.indexOf('}', index) + 1;
				String reqName = uidAttr.substring(index + 2, lastIndex - 1);
				b.append(req.getParameter(reqName));
				index = uidAttr.indexOf('$', index + 1);
			}
			b.append(uidAttr.substring(lastIndex));
			filter = b.toString();

		} else {
			StringBuffer b = new StringBuffer();
			b.append("(").append(uidAttr).append("=").append(username).append(")");
			filter = b.toString();
		}

		AuthInfo authInfo = null;

		try {
			LDAPSearchResults res = cfgMgr.getMyVD().search(AuthUtil.getChainRoot(cfgMgr, act), 2, filter,
					new ArrayList<String>());

			if (res.hasMore()) {
				LDAPEntry entry = res.next();
				while (res.hasMore())
					res.next();

				Iterator<LDAPAttribute> it = entry.getAttributeSet().iterator();
				authInfo = new AuthInfo(entry.getDN(), authMechName, act.getName(), act.getLevel(),(TremoloHttpSession) req.getSession());

				while (it.hasNext()) {
					LDAPAttribute attrib = it.next();
					Attribute attr = new Attribute(attrib.getName());
					LinkedList<ByteArray> vals = attrib.getAllValues();
					for (ByteArray val: vals) {
						attr.getValues().add(new String(val.getValue()));
					}
					authInfo.getAttribs().put(attr.getName(), attr);
				}

			}

		} catch (LDAPException e) {
			logger.error("Could not find user", e);
		}

		return authInfo;

	}
	
	
	private AuthInfo findUser(String credentialId, String credentialIdAttribute, AuthChainType act,
			HttpServletRequest req, ConfigManager cfgMgr, String authMechName) {
		String filter = "";
		
		StringBuffer b = new StringBuffer();
		b.append("(").append(credentialIdAttribute).append("=").append(credentialId).append(")");
		filter = b.toString();
	

		AuthInfo authInfo = null;

		try {
			LDAPSearchResults res = cfgMgr.getMyVD().search(AuthUtil.getChainRoot(cfgMgr, act), 2, filter,
					new ArrayList<String>());

			if (res.hasMore()) {
				LDAPEntry entry = res.next();
				while (res.hasMore())
					res.next();

				Iterator<LDAPAttribute> it = entry.getAttributeSet().iterator();
				authInfo = new AuthInfo(entry.getDN(), authMechName, act.getName(), act.getLevel(),(TremoloHttpSession) req.getSession());

				while (it.hasNext()) {
					LDAPAttribute attrib = it.next();
					Attribute attr = new Attribute(attrib.getName());
					LinkedList<ByteArray> vals = attrib.getAllValues();
					for (ByteArray val: vals) {
						attr.getValues().add(new String(val.getValue()));
					}
					authInfo.getAttribs().put(attr.getName(), attr);
				}

			}

		} catch (LDAPException e) {
			logger.error("Could not find user", e);
		}

		return authInfo;

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
