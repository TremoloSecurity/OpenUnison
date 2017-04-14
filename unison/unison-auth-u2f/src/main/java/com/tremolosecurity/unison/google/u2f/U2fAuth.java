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

import java.io.IOException;
import java.net.MalformedURLException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.google.gson.Gson;
import com.google.u2f.U2FException;
import com.google.u2f.server.ChallengeGenerator;
import com.google.u2f.server.U2FServer;
import com.google.u2f.server.data.SecurityKeyData;
import com.google.u2f.server.impl.BouncyCastleCrypto;
import com.google.u2f.server.messages.SignResponse;
import com.google.u2f.server.messages.U2fSignRequest;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.AuthMechType;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.ProvisioningParams;
import com.tremolosecurity.provisioning.service.util.TremoloUser;
import com.tremolosecurity.provisioning.service.util.WFCall;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.auth.AuthMechanism;
import com.tremolosecurity.proxy.auth.RequestHolder;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.u2f.util.U2fUtil;


public class U2fAuth implements AuthMechanism {
	private static final String AUTH_SIGN_REQ = "com.tremolosecurity.unison.google.u2f.sig_req";

	private static final String AUTH_SIGN_REQ_JSON = "com.tremolosecurity.unison.google.u2f.sig_req_json";

	private static final String SERVER = "com.tremolosecurity.unison.google.u2f.u2f";;
	
	static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(U2fAuth.class.getName());

	private ChallengeGenerator challengeGen;
	
	
	@Override
	public void init(ServletContext ctx, HashMap<String, Attribute> init) {
		this.challengeGen = new ChallengeGenerator() {
			 private final SecureRandom random = new SecureRandom();

			@Override
			public byte[] generateChallenge(String accountName) {
				byte[] randomBytes = new byte[32];
		        random.nextBytes(randomBytes);
		        return randomBytes;
			}
			 
			 
		};

	}

	@Override
	public String getFinalURL(HttpServletRequest request, HttpServletResponse response) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void doGet(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		if (request.getParameter("signResponse") == null) {
			startAuthentication(request, response, as);
		} else {
			Gson gson = new Gson();
			SignResponseHolder srh = gson.fromJson(request.getParameter("signResponse"),SignResponseHolder.class);
			
			AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
			HttpSession session = ((HttpServletRequest) request).getSession(); //SharedSession.getSharedSession().getSession(req.getSession().getId());
			UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
			RequestHolder reqHolder = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
			String urlChain = holder.getUrl().getAuthChain();
			AuthChainType act = holder.getConfig().getAuthChains().get(reqHolder.getAuthChainName());
			AuthMechType amt = act.getAuthMech().get(as.getId());
			HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
			String challengeStoreAttribute = authParams.get("attribute").getValues().get(0); 
			String encyrptionKeyName = authParams.get("encryptionKeyName").getValues().get(0);
			String uidAttributeName = authParams.get("uidAttributeName").getValues().get(0);
			String workflowName = authParams.get("workflowName").getValues().get(0);
			
			
			if (srh.getErrorCode() > 0) {
				logger.warn("Browser could not validate u2f token for user '" + userData.getUserDN() + "' : " + srh.getErrorCode());
				if (amt.getRequired().equals("required")) {
					as.setSuccess(false);
					
				} 
				
				
				holder.getConfig().getAuthManager().nextAuth(request, response,session,false);
				return;
			}
			
			U2FServer u2f = (U2FServer) request.getSession().getAttribute(SERVER);
			
			SignResponse sigResp = new SignResponse(srh.getKeyHandle(),srh.getSignatureData(),srh.getClientData(),srh.getSessionId());
			
			
			try {
				u2f.processSignResponse(sigResp);
			} catch (U2FException e) {
				logger.warn("Could not authenticate user : '" + e.getMessage() + "'");
				if (amt.getRequired().equals("required")) {
					as.setSuccess(false);
					
				} 
				
				
				holder.getConfig().getAuthManager().nextAuth(request, response,session,false);
				return;
			}
			
			String encrypted;
			try {
				encrypted = U2fUtil.encode(u2f.getAllSecurityKeys("doesntmatter"),encyrptionKeyName);
			} catch (Exception e) {
				throw new ServletException("Could not encrypt keys");
			}
			WFCall wc = new WFCall();
			wc.setName(workflowName);
			wc.setUidAttributeName(uidAttributeName);
			TremoloUser tu = new TremoloUser();
			tu.setUid(userData.getAttribs().get(uidAttributeName).getValues().get(0));
			tu.getAttributes().add(new Attribute(uidAttributeName,userData.getAttribs().get(uidAttributeName).getValues().get(0)));
			tu.getAttributes().add(new Attribute(challengeStoreAttribute,encrypted));
			wc.setUser(tu);
			Map<String,Object> req = new HashMap<String,Object>();
			req.put(ProvisioningParams.UNISON_EXEC_TYPE, ProvisioningParams.UNISON_EXEC_SYNC);
			wc.setRequestParams(req);
			
			try {
				GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getWorkFlow(workflowName).executeWorkflow(wc);
			} catch (ProvisioningException e) {
				throw new ServletException("Could not save keys",e);
			}
			
			as.setSuccess(true);
			holder.getConfig().getAuthManager().nextAuth(request, response,session,false);
		}
		

	}

	private void startAuthentication(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws ServletException, MalformedURLException, IOException {
		AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
		HttpSession session = ((HttpServletRequest) request).getSession(); //SharedSession.getSharedSession().getSession(req.getSession().getId());
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		RequestHolder reqHolder = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
		String urlChain = holder.getUrl().getAuthChain();
		AuthChainType act = holder.getConfig().getAuthChains().get(reqHolder.getAuthChainName());
		AuthMechType amt = act.getAuthMech().get(as.getId());
		HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
		String challengeStoreAttribute = authParams.get("attribute").getValues().get(0); 
		String encyrptionKeyName = authParams.get("encryptionKeyName").getValues().get(0);
		String uidAttributeName = authParams.get("uidAttributeName").getValues().get(0);
		String formURI = authParams.get("formURI").getValues().get(0);
		
		List<SecurityKeyData> keys;
		try {
			keys = U2fUtil.loadUserKeys(userData, challengeStoreAttribute, encyrptionKeyName);
		} catch (Exception e1) {
			throw new ServletException("Could not loak keys",e1);
		}
		Set<String> origins = new HashSet<String>();
		String appID = U2fUtil.getApplicationId(request);
		origins.add(appID);
		U2FServer u2f = new U2FServerUnison(this.challengeGen,new UnisonDataStore(UUID.randomUUID().toString(),keys),new BouncyCastleCrypto(),origins);
		
		String uid = userData.getAttribs().get(uidAttributeName).getValues().get(0);
		
		if (keys == null || keys.size() == 0) {
			if (amt.getRequired().equals("required")) {
				as.setSuccess(false);
				
			} 
			
			
			holder.getConfig().getAuthManager().nextAuth(request, response,session,false);
			return;
		} 
		
		U2fSignRequest sigReq = null;
		try {
			sigReq = u2f.getSignRequest(uid, appID);
		} catch (U2FException e) {
			logger.error("Could not start authentication",e);
			if (amt.getRequired().equals("required")) {
				as.setSuccess(false);
				
			} 
			
			
			holder.getConfig().getAuthManager().nextAuth(request, response,session,false);
			return;
		}
		Gson gson = new Gson();
		request.getSession().setAttribute(AUTH_SIGN_REQ, sigReq);
		request.getSession().setAttribute(AUTH_SIGN_REQ_JSON, gson.toJson(sigReq));
		request.getSession().setAttribute(SERVER, u2f);
		
		response.sendRedirect(formURI);
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
