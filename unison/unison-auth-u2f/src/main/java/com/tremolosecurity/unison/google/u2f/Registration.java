/*******************************************************************************
 * Copyright 2017 Tremolo Security, Inc.
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
package com.tremolosecurity.unison.google.u2f;

import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import com.google.gson.Gson;
import com.google.u2f.U2FException;
import com.google.u2f.server.ChallengeGenerator;
import com.google.u2f.server.U2FServer;
import com.google.u2f.server.data.SecurityKeyData;
import com.google.u2f.server.impl.BouncyCastleCrypto;
import com.google.u2f.server.messages.RegistrationRequest;
import com.google.u2f.server.messages.RegistrationResponse;
import com.tremolosecurity.provisioning.core.ProvisioningParams;
import com.tremolosecurity.provisioning.service.util.TremoloUser;
import com.tremolosecurity.provisioning.service.util.WFCall;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.u2f.util.U2fUtil;



public class Registration implements HttpFilter {

	public static final String REGISTRATION_REQUEST = "com.tremolosecurity.unison.u2f.Registration.request";
	private static final String REGISTRATION_URI = "com.tremolosecurity.unison.u2f.Registration.url";
	private static final String REGISTRATION_REQUEST_JSON = "com.tremolosecurity.unison.u2f.Registration.request_json";
	private static final String SERVER = "com.tremolosecurity.unison.u2f.Registration.server";;
	static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(Registration.class.getName());
	static Gson gson = new Gson();
	
	
	String encyrptionKeyName;
	String challengeStoreAttribute;
	String challengeURI;
	String workflowName;
	
	String uidAttributeName;
	String registrationCompleteURI;
	
	boolean requireAttestation;
	HashSet<X509Certificate> attestationCerts;
	
	
	ChallengeGenerator challengeGen;
	
	
	
	@Override
	public void doFilter(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		if (request.getMethod().equalsIgnoreCase("GET")) {
			//TODO switch this off
			
			AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
			String accountName = userData.getAttribs().get(this.uidAttributeName).getValues().get(0);
			List<SecurityKeyData> keys = U2fUtil.loadUserKeys(userData, challengeStoreAttribute, encyrptionKeyName);
			Set<String> origins = new HashSet<String>();
			String appID = U2fUtil.getApplicationId(request.getServletRequest());
			origins.add(appID);
			U2FServer u2f = new U2FServerUnison(this.challengeGen,new UnisonDataStore(UUID.randomUUID().toString(),keys,(this.requireAttestation ? this.attestationCerts : new HashSet<X509Certificate>())),new BouncyCastleCrypto(),origins,this.requireAttestation);
			RegistrationRequest regRequest = u2f.getRegistrationRequest(accountName, appID);
			request.getSession().setAttribute(Registration.REGISTRATION_REQUEST_JSON, gson.toJson(regRequest));
			request.getSession().setAttribute(Registration.REGISTRATION_REQUEST, regRequest);
			request.getSession().setAttribute(Registration.SERVER, u2f);
			request.setAttribute(REGISTRATION_URI, request.getRequestURL().toString());
			request.getRequestDispatcher(this.challengeURI).forward(request.getServletRequest(), response.getServletResponse());
			
			
		} else if (request.getMethod().equalsIgnoreCase("POST")) {
			U2FServer u2f = (U2FServer) request.getSession().getAttribute(SERVER);
			if (logger.isDebugEnabled()) {
				logger.debug("response : '" + request.getParameter("tokenResponse").getValues().get(0) + "'");
			}
			RegistrationResponseHolder rrh = gson.fromJson(request.getParameter("tokenResponse").getValues().get(0), RegistrationResponseHolder.class);
			RegistrationResponse rr = new RegistrationResponse(rrh.getRegistrationData(),rrh.getClientData(),rrh.getClientData());
			try {
				u2f.processRegistrationResponse(rr, System.currentTimeMillis());
			} catch (U2FException e) {
				logger.error("Could not register",e);
				request.setAttribute("register.result", false);
				request.getRequestDispatcher(this.registrationCompleteURI).forward(request.getServletRequest(), response.getServletResponse());
				return;
			}
			AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
			String encrypted = U2fUtil.encode(u2f.getAllSecurityKeys("doesntmatter"),encyrptionKeyName);
			WFCall wc = new WFCall();
			wc.setName(this.workflowName);
			wc.setUidAttributeName(this.uidAttributeName);
			TremoloUser tu = new TremoloUser();
			tu.setUid(userData.getAttribs().get(this.uidAttributeName).getValues().get(0));
			tu.getAttributes().add(new Attribute(this.uidAttributeName,userData.getAttribs().get(this.uidAttributeName).getValues().get(0)));
			tu.getAttributes().add(new Attribute(this.challengeStoreAttribute,encrypted));
			wc.setUser(tu);
			Map<String,Object> req = new HashMap<String,Object>();
			req.put(ProvisioningParams.UNISON_EXEC_TYPE, ProvisioningParams.UNISON_EXEC_SYNC);
			wc.setRequestParams(req);
			
			GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getWorkFlow(this.workflowName).executeWorkflow(wc);
			request.setAttribute("register.result", true);
			request.getRequestDispatcher(this.registrationCompleteURI).forward(request.getServletRequest(), response.getServletResponse());
			
		}

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
		this.challengeGen = new ChallengeGenerator() {
			 private final SecureRandom random = new SecureRandom();

			@Override
			public byte[] generateChallenge(String accountName) {
				byte[] randomBytes = new byte[32];
		        random.nextBytes(randomBytes);
		        return randomBytes;
			}
			 
			 
		};
		
		this.encyrptionKeyName = loadAttributeValue("encryptionKeyName","Encryption Key",config);
		this.challengeStoreAttribute = loadAttributeValue("attribute","Attribute Name",config);
		this.challengeURI = loadAttributeValue("challengeURI","Challenge URI",config);
		this.workflowName = loadAttributeValue("workflowName","Workflow Name",config);
		
		this.uidAttributeName = loadAttributeValue("uidAttributeName","UID Attribute Name",config );
		this.registrationCompleteURI = loadAttributeValue("completedURI","Registration Completed URI",config );
		this.requireAttestation = loadAttributeValue("requireAttestation","RequireAttestation",config ).equalsIgnoreCase("true");
		
		Attribute certNames = config.getAttribute("trustedCertificate");
		this.attestationCerts = new HashSet<X509Certificate>();
		if (certNames != null) {
			for (String certName : certNames.getValues()) {
				if (GlobalEntries.getGlobalEntries().getConfigManager().getCertificate(certName) != null) {
					this.attestationCerts.add(GlobalEntries.getGlobalEntries().getConfigManager().getCertificate(certName));
				}
			}
		}

	}
	
	private String loadAttributeValue(String name,String label,HttpFilterConfig config) throws Exception {
		Attribute attr = config.getAttribute(name);
		if (attr == null) {
			throw new Exception(label + " not found");
		}
		
		String val = attr.getValues().get(0);
		logger.info(label + ": '" + val + "'");
		
		return val;
	}

}
