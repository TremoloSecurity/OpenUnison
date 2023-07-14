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
package com.tremolosecurity.proxy.filters;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.tremolosecurity.provisioning.core.ProvisioningParams;
import com.tremolosecurity.provisioning.service.util.TremoloUser;
import com.tremolosecurity.provisioning.service.util.WFCall;
import com.tremolosecurity.provisioning.util.EncryptedMessage;
import com.tremolosecurity.proxy.ProxySys;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.auth.webauthn.OpenUnisonAuthenticator;
import com.tremolosecurity.proxy.auth.webauthn.WebAuthnUserData;
import com.tremolosecurity.proxy.auth.webauthn.WebAuthnUtils;
import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AttestationConveyancePreference;
import com.webauthn4j.data.AuthenticatorAttachment;
import com.webauthn4j.data.AuthenticatorSelectionCriteria;
import com.webauthn4j.data.PublicKeyCredentialCreationOptions;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialRequestOptions;
import com.webauthn4j.data.PublicKeyCredentialRpEntity;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.PublicKeyCredentialUserEntity;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.UserVerificationRequirement;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.util.exception.WebAuthnException;
import com.webauthn4j.validator.exception.ValidationException;

public class WebAuthnRegistration implements HttpFilter {
	
	static Logger logger = Logger.getLogger(WebAuthnRegistration.class.getName());

	String uidAttributeName;
	String displayName;
	SecureRandom secureRandom;
	
	String challengeURI;
	String encryptionKeyName;
	
	String workflowName;
	String challengeStoreAttribute;
	
	String credentialIdAttribute;
	
	boolean requireResisentKey;
	AuthenticatorAttachment authenticatorAttachment;
	UserVerificationRequirement userVerificationRequirement;
	
	@Override
	public void doFilter(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		request.getServletRequest().setAttribute("com.tremolosecurity.unison.proxy.noRedirectOnError", "com.tremolosecurity.unison.proxy.noRedirectOnError");
		
		if (request.getMethod().equalsIgnoreCase("GET")) {
			if (request.getRequestURI().toLowerCase().endsWith("/credentialcreateoptions")) {
				ObjectConverter oc = new  ObjectConverter();
				String rpId = getRpId(request.getServletRequest());
				AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
				
				WebAuthnUserData webAuthnUserData = WebAuthnUtils.lookupWebAuthnUserData(userData, challengeStoreAttribute, encryptionKeyName);
				
				if (webAuthnUserData == null) {
					//no data yet, let's create
					
					webAuthnUserData = new WebAuthnUserData(userData.getAttribs().get(this.uidAttributeName).getValues().get(0));
					WebAuthnUtils.storeWebAuthnUserData(webAuthnUserData, this.encryptionKeyName, userData,this.workflowName, this.uidAttributeName, this.challengeStoreAttribute);
					
				}
				
				
				
		        Challenge challenge = new DefaultChallenge();
		        CborConverter cbor = oc.getCborConverter();
		        String b64UrlChallenge = Base64UrlUtil.encodeToString(challenge.getValue());
		        
		        
		        AuthenticatorSelectionCriteria authenticatorSelectionCriteria =
		                new AuthenticatorSelectionCriteria(
		                		authenticatorAttachment,
		                		requireResisentKey,
		                		userVerificationRequirement);
		
		        PublicKeyCredentialParameters publicKeyCredentialParameters = new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256);
		        
		        
		        String b64UrlId = Base64.getUrlEncoder().encodeToString(webAuthnUserData.getId());
		        
		        ServerProperty serverProperty = new ServerProperty(new Origin(request.getRequestURL().toString()), rpId, challenge, webAuthnUserData.getId());
		        
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
		        
		        request.getSession().setAttribute("tremolo.io/webauthn/serverProperty", serverProperty);
		        
		        PublicKeyCredentialUserEntity publicKeyCredentialUserEntity = new PublicKeyCredentialUserEntity(webAuthnUserData.getId(), webAuthnUserData.getDisplayName() , webAuthnUserData.getDisplayName());
		
		        AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> extensions = new AuthenticationExtensionsClientInputs<>();
		        PublicKeyCredentialCreationOptions credentialCreationOptions
		                = new PublicKeyCredentialCreationOptions(
		                new PublicKeyCredentialRpEntity(rpId, rpId),
		                publicKeyCredentialUserEntity,
		                challenge,
		                Collections.singletonList(publicKeyCredentialParameters),
		                null,
		                Collections.emptyList(),
		                authenticatorSelectionCriteria,
		                AttestationConveyancePreference.NONE,
		                extensions
		        );
		        
		        
		        
		        ObjectMapper mapper = new ObjectMapper();
		        String publecCredentialCreationOptionsJson = oc.getJsonConverter().writeValueAsString(credentialCreationOptions);//mapper.writeValueAsString(credentialCreationOptions);
		        
		        JSONObject root = (JSONObject) new JSONParser().parse(publecCredentialCreationOptionsJson);
		        
		        root.put("challenge", b64UrlChallenge);
		        ((JSONObject) root.get("user")).put("id", b64UrlId);
		        
		        
		        JSONObject publicKeyRoot = new JSONObject();
		        publicKeyRoot.put("publicKey", root);
		        
		        publicKeyRoot.put("serverProperty", Base64.getUrlEncoder().encodeToString(yourBytes));
		        
		        
		        response.getWriter().println(publicKeyRoot.toString());
			} else {
				StringBuilder createCredentialURL = new StringBuilder(request.getRequestURL().toString());
				createCredentialURL.append("/credentialCreateOptions");
				request.setAttribute("tremolo.io/webauthn/challengeurl", createCredentialURL.toString());
				
				
				
				createCredentialURL = new StringBuilder(request.getRequestURL().toString());
				createCredentialURL.append("/finishregistration");
				request.setAttribute("tremolo.io/webauthn/finishregistration", createCredentialURL.toString());
				
				
				request.getRequestDispatcher(this.challengeURI).forward(request.getServletRequest(), response.getServletResponse());
			}
		} else if (request.getMethod().equalsIgnoreCase("POST")) {
			
			
			
			
			try {
				storeCredential(request);
			} catch (WebAuthnException e) {
				JSONObject resp = new JSONObject();
				resp.put("error", e.getMessage());
				response.sendError(500);
				response.getWriter().println(resp.toString());
			}
			
			catch (Throwable t) {
				JSONObject resp = new JSONObject();
				logger.error("Could not store credential",t);
				resp.put("error", "There was an error, please contanct your system administrator");
				response.sendError(500);
				response.getWriter().println(resp.toString());
			}
			
			
			
		}

	}


	private void storeCredential(HttpFilterRequest request)
			throws ParseException, IOException, ClassNotFoundException, ServletException, Exception {
		byte[] requestBytes = (byte[]) request.getAttribute(ProxySys.MSG_BODY);
		String requestString = new String(requestBytes,StandardCharsets.UTF_8);
		
		JSONObject root = (JSONObject) new JSONParser().parse(requestString);
		
		
		if (root.get("label") == null || ((String)root.get("label")).isEmpty()) {
			throw new WebAuthnException("Label required");
		}
		
		ByteArrayInputStream bais = new ByteArrayInputStream(Base64.getUrlDecoder().decode((String) root.get("serverProperty")));
		ObjectInputStream ois = new ObjectInputStream(bais);
		ServerProperty serverProperty = (ServerProperty) ois.readObject();
		
		
		byte[] attestationObject = Base64.getUrlDecoder().decode((String) root.get("attestationObject"));
		byte[] clientDataJSON = Base64.getUrlDecoder().decode((String) root.get("clientDataJSON"));
		String clientExtensionJSON = (String) root.get("clientExtResults");  
		Set<String> transports = new HashSet<String>();
		
		
		// expectations
		boolean userVerificationRequired = false;
		boolean userPresenceRequired = true;
		
		RegistrationRequest registrationRequest = new RegistrationRequest(attestationObject, clientDataJSON, clientExtensionJSON, transports);
		RegistrationParameters registrationParameters = new RegistrationParameters(serverProperty, userVerificationRequired, userPresenceRequired);
		RegistrationData registrationData;
		WebAuthnManager webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager();
		try {
		    registrationData = webAuthnManager.parse(registrationRequest);
		} catch (DataConversionException e) {
		    // If you would like to handle WebAuthn data structure parse error, please catch DataConversionException
		    throw e;
		}
		try {
		    webAuthnManager.validate(registrationData, registrationParameters);
		} catch (ValidationException e) {
		    // If you would like to handle WebAuthn data validation error, please catch ValidationException
		    throw e;
		}
		
		OpenUnisonAuthenticator authenticator =
		        new OpenUnisonAuthenticator((String) root.get("label"),
		                registrationData.getAttestationObject().getAuthenticatorData().getAttestedCredentialData(),
		                registrationData.getAttestationObject().getAttestationStatement(),
		                registrationData.getAttestationObject().getAuthenticatorData().getSignCount()
		        );
		
		AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
		
		WebAuthnUserData webAuthnUserData = WebAuthnUtils.lookupWebAuthnUserData(userData, this.challengeStoreAttribute, this.encryptionKeyName);
		
		if (webAuthnUserData == null) {
			throw new Exception("No webauthn user data, should not happen");
		}
		
		
		for (OpenUnisonAuthenticator auth : webAuthnUserData.getAuthenticators()) {
			if (auth.getLabel().equals(authenticator.getLabel())) {
				throw new WebAuthnException("Label already exists, choose another label");
			}
		}
		
		webAuthnUserData.getAuthenticators().add(authenticator);
		
		if (this.credentialIdAttribute != null) {
			WebAuthnUtils.storeWebAuthnUserData(webAuthnUserData, encryptionKeyName, userData, workflowName, uidAttributeName, challengeStoreAttribute,this.credentialIdAttribute,authenticator);
		} else {
			WebAuthnUtils.storeWebAuthnUserData(webAuthnUserData, encryptionKeyName, userData, workflowName, uidAttributeName, challengeStoreAttribute);
		}
	} 
	
	
	public static String getRpId(HttpServletRequest request) throws MalformedURLException {
		StringBuffer appID = new StringBuffer();
		URL url = new URL(request.getRequestURL().toString());
		return url.getHost();

		
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

	@Override
	public void initFilter(HttpFilterConfig config) throws Exception {
		this.uidAttributeName = config.getAttribute("uidAttributeName").getValues().get(0);
		this.displayName = config.getAttribute("displayName").getValues().get(0);
		this.secureRandom = new SecureRandom();
		this.challengeURI = config.getAttribute("challengeURI").getValues().get(0);
		this.encryptionKeyName = config.getAttribute("encryptionKeyName").getValues().get(0);
		this.workflowName = config.getAttribute("workflowName").getValues().get(0);
		this.challengeStoreAttribute = config.getAttribute("challengStoreAttribute").getValues().get(0);
		
		if (config.getAttribute("authenticationAttachment") != null) {
			this.authenticatorAttachment = AuthenticatorAttachment.create(config.getAttribute("authenticationAttachment").getValues().get(0));
		} else {
			this.authenticatorAttachment = null;
		}
		this.userVerificationRequirement = UserVerificationRequirement.create(config.getAttribute("userVerificationRequirement").getValues().get(0));
		this.requireResisentKey = config.getAttribute("requireResidentKey").getValues().get(0).equalsIgnoreCase("true");
		
		if (config.getAttribute("credentialIdAttributeName") != null) {
			this.credentialIdAttribute = config.getAttribute("credentialIdAttributeName").getValues().get(0);
			
		} else {
			this.credentialIdAttribute = null;
		}
	}

}
