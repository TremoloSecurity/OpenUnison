/*******************************************************************************
 * Copyright 2021 Tremolo Security, Inc.
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
package com.tremolosecurity.idp.providers;

import static org.apache.directory.ldap.client.api.search.FilterBuilder.equal;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.UUID;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.apache.log4j.Logger;
import org.joda.time.DateTime;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.google.gson.Gson;
import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.ApplicationType;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.idp.providers.oidc.db.StsRequest;
import com.tremolosecurity.idp.providers.oidc.model.OidcSessionState;
import com.tremolosecurity.log.AccessLog;
import com.tremolosecurity.log.AccessLog.AccessEvent;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.auth.AzSys;
import com.tremolosecurity.proxy.auth.PostAuthSuccess;
import com.tremolosecurity.proxy.auth.RequestHolder;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.myvd.MyVDConnection;
import com.tremolosecurity.proxy.util.NextSys;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.proxy.util.ProxyTools;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;

public class TokenPostAuth implements PostAuthSuccess {

	static Logger logger = Logger.getLogger(TokenPostAuth.class);
	
	AzSys azSys;
	
	OpenIDConnectTransaction transaction;
	OpenIDConnectTrust trust;
	StsRequest stsRequest;
	OpenIDConnectIdP idp;
	
	public TokenPostAuth(OpenIDConnectTransaction transaction,OpenIDConnectTrust trust,StsRequest stsRequest,OpenIDConnectIdP idp) {
		this.azSys = new AzSys();
		
		
		this.transaction = transaction;
		this.trust = trust;
		this.stsRequest = stsRequest;
		this.idp = idp;
	}
	
	@Override
	public void runAfterSuccessfulAuthentication(HttpServletRequest req, HttpServletResponse resp, UrlHolder holder,
			AuthChainType act, RequestHolder reqHolder, AuthController actl, NextSys next)
			throws IOException, ServletException {
		

		String subjectUid; 
		String amr;
		
		HttpSession session = req.getSession();
		AuthInfo authData = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
		
		if (! azSys.checkRules(authData, GlobalEntries.getGlobalEntries().getConfigManager(), trust.getClientAzRules(), new HashMap<String,Object>())) {
			AccessLog.log(AccessEvent.AzFail, holder.getApp(), req, authData, "client not authorized for token exchange");
			resp.sendError(403);
			return;
		} 
		
		
		if (! trust.getAllowedAudiences().contains(stsRequest.getAudience())) {
			AccessLog.log(AccessEvent.AzFail, holder.getApp(), req, authData, new StringBuilder().append("Audience '").append(stsRequest.getAudience()).append("' is not an authorized audience for sts '").append(trust.getTrustName()).append("'").toString());
			resp.sendError(403);
			return;
		}
		
		OpenIDConnectTrust targetTrust = idp.getTrusts().get(stsRequest.getAudience());
		if (targetTrust == null) {
			logger.warn(new StringBuilder().append("Audience '").append(stsRequest.getAudience()).append("' does not exist").toString());
			
			resp.sendError(404);
			return;
		}
		
		X509Certificate sigCert = GlobalEntries.getGlobalEntries().getConfigManager().getCertificate(idp.getJwtSigningKeyName());
		
		if (sigCert == null) {
			logger.error(new StringBuilder().append("JWT Signing Certificate '").append(idp.getJwtSigningKeyName()).append("' does not exist").toString());
			resp.sendError(500);
			return;
		}
		
		JsonWebSignature jws = new JsonWebSignature();
		try {
			jws.setCompactSerialization(stsRequest.getSubjectToken());
			jws.setKey(sigCert.getPublicKey());
			if (! jws.verifySignature()) {
				AccessLog.log(AccessEvent.AzFail, holder.getApp(), req, authData, new StringBuilder().append("Invalid subject_token signature").toString());
				resp.sendError(403);
				return;
			}
			
			String json = jws.getPayload();
			JSONObject obj = (JSONObject) new JSONParser().parse(json);
			long exp = ((Long)obj.get("exp")) * 1000L;
			long nbf = ((Long)obj.get("nbf")) * 1000L;
			
			if (new DateTime(exp).isBeforeNow()) {
				AccessLog.log(AccessEvent.AzFail, holder.getApp(), req, authData, new StringBuilder().append("subject_token has expired").toString());
				resp.sendError(403);
				return;
			}
			
			if (new DateTime(nbf).isAfterNow()) {
				AccessLog.log(AccessEvent.AzFail, holder.getApp(), req, authData, new StringBuilder().append("subject_token is not yet valid").toString());
				resp.sendError(403);
				return;
			}
			
			StringBuffer issuer = new StringBuffer();
			
			
			//issuer.append(cfg.getAuthIdPPath()).append(this.idpName);
			issuer.append(holder.getApp().getUrls().getUrl().get(0).getUri());
			
			String issuerUrl = ProxyTools.getInstance().getFqdnUrl(issuer.toString(), req);
			
			if (! ((String) obj.get("iss")).equals(issuerUrl)) {
				AccessLog.log(AccessEvent.AzFail, holder.getApp(), req, authData, new StringBuilder().append("subject_token has an invalid issuer").toString());
				resp.sendError(403);
				return;
			}
			
			subjectUid = (String) obj.get("sub");
			if (subjectUid == null) {
				logger.error("Subject has no sub claim");
				resp.sendError(422);
				return;
			}
			
			JSONArray amrs = (JSONArray) obj.get("amr");
			if (amrs == null) {
				logger.warn("subject_token does not contain an amr claim");
				resp.sendError(422);
				return;
			}
			
			amr = (String) amrs.get(0);
			
			
		} catch (JoseException | ParseException e) {
			throw new ServletException("Could not verify subject JWT",e);
		}
		
		// load the user 
		
		String uidAttribute = idp.getUidAttributeFromMap();
		if (uidAttribute == null) {
			logger.error(new StringBuilder().append("IdP ").append(holder.getApp().getName()).append(" does not have a sub attribute mapped to a user attribute").toString());
			resp.sendError(500);
			return;
		}
		
		String authChainName = idp.getAmrToAuthChain().get(amr);
		if (authChainName == null) {
			logger.warn(new StringBuilder("subject_token amr '").append(amr).append("' does not map to any authentication chains").toString());
			resp.sendError(422);
			return;
		}
		
		
		
		AuthInfo subjectForAz = this.lookupUser(session, GlobalEntries.getGlobalEntries().getConfigManager().getMyVD(), uidAttribute, act, subjectUid,authChainName);
		if (subjectForAz == null) {
			logger.error(new StringBuilder().append("STS exchange for sub '").append(subjectUid).append("' failed because user not found"));
			resp.sendError(422);
			return;
		}
		
		
		// with a subject in hand, authorize that we're able to take care of 
		if (! azSys.checkRules(subjectForAz, GlobalEntries.getGlobalEntries().getConfigManager(), trust.getSubjectAzRules(), new HashMap<String,Object>())) {
			AccessLog.log(AccessEvent.AzFail, holder.getApp(), req, authData, new StringBuilder().append("client not authorized to exchange token for subject '").append(subjectUid).append("'").toString());
			resp.sendError(403);
			return;
		} 
		
		if (this.stsRequest.isImpersonation() && ! trust.isStsImpersonation()) {
			AccessLog.log(AccessEvent.AzFail, holder.getApp(), req, authData, new StringBuilder().append("client '").append(trust.getTrustName()).append("' authorized for impersonation").toString());
			resp.sendError(403);
			return;
		}
		
		if (this.stsRequest.isDelegation() && ! trust.isStsDelegation()) {
			AccessLog.log(AccessEvent.AzFail, holder.getApp(), req, authData, new StringBuilder().append("client '").append(trust.getTrustName()).append("' authorized for delegation").toString());
			resp.sendError(403);
			return;
		}
		
		
		
		OpenIDConnectAccessToken access = new OpenIDConnectAccessToken();
		
		OidcSessionState oidcSession = idp.createUserSession(req, stsRequest.getAudience(), holder, targetTrust, subjectForAz.getUserDN(), GlobalEntries.getGlobalEntries().getConfigManager(), access,UUID.randomUUID().toString(),subjectForAz.getAuthChain()); 
		
		
		if (this.stsRequest.isImpersonation()) {
			AccessLog.log(AccessEvent.AzSuccess, holder.getApp(), req, authData, new StringBuilder().append("client '").append(trust.getTrustName()).append("' impersonating '").append(subjectUid).append("', jti : '").append(access.getIdTokenId()).append("'").toString());
		}
		
		
		String idtoken = access.getId_token();
		
		
		access.setRefresh_token(oidcSession.getRefreshToken());
		
		
		Gson gson = new Gson();
		String json = gson.toJson(access);
		
		resp.setContentType("application/json");
		resp.getOutputStream().write(json.getBytes("UTF-8"));
		resp.getOutputStream().flush();
		
		if (logger.isDebugEnabled()) {
			logger.debug("Token JSON : '" + json + "'");
		}
		
	}
	
	private  AuthInfo  lookupUser(HttpSession session, MyVDConnection myvd, String uidAttr,
			AuthChainType act,String uid,String subjectAuthMethod) throws ServletException {
		
		
		
		String filter = "";
		
		StringBuffer b = new StringBuffer();
		String userParam = uid;
		b.append('(').append(uidAttr).append('=').append(userParam).append(')');
		if (userParam == null) {
			filter = "(!(objectClass=*))";
		} else {
			filter = equal(uidAttr,userParam).toString();
		}
		
		
		try {
			
			String root = act.getRoot();
			if (root == null || root.trim().isEmpty()) {
				root = GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getLdapRoot();
			}
			
			LDAPSearchResults res = myvd.search(root, 2, filter, new ArrayList<String>());
			
			if (res.hasMore()) {
				LDAPEntry entry = res.next();
				while (res.hasMore()) res.next();
				
				AuthChainType actForSubject = GlobalEntries.getGlobalEntries().getConfigManager().getAuthChains().get(subjectAuthMethod);
				if (actForSubject == null) {
					logger.warn(new StringBuilder("No authentication chain named '").append(subjectAuthMethod).append("'"));
				}
				
				AuthInfo authInfo = new AuthInfo(entry.getDN(),(String) session.getAttribute(ProxyConstants.AUTH_MECH_NAME),actForSubject.getName(),actForSubject.getLevel());
				User user = new User(entry);
				user = idp.getMapper().mapUser(user);
				
				for (String attrName : user.getAttribs().keySet()) {
					authInfo.getAttribs().put(attrName, user.getAttribs().get(attrName));
				}
				
				return authInfo;
			}  else {
				return null;
			}
			
		} catch (LDAPException | ProvisioningException e) {
			throw new ServletException("Could not lookup sts subject",e);
		}
	}

}
