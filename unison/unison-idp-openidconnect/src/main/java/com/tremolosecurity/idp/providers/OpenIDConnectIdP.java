/*******************************************************************************
 * Copyright 2015, 2018 Tremolo Security, Inc.
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
package com.tremolosecurity.idp.providers;

import static org.apache.directory.ldap.client.api.search.FilterBuilder.equal;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.UUID;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.GZIPOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;
import java.util.zip.ZipOutputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Category;
import org.apache.log4j.Logger;
import org.apache.xml.security.utils.Base64;
import org.hibernate.Query;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.boot.MetadataSources;
import org.hibernate.boot.cfgxml.spi.LoadedConfig;
import org.hibernate.boot.jaxb.cfg.spi.JaxbCfgHibernateConfiguration;
import org.hibernate.boot.jaxb.cfg.spi.JaxbCfgMappingReferenceType;
import org.hibernate.boot.jaxb.cfg.spi.JaxbCfgHibernateConfiguration.JaxbCfgSessionFactory;
import org.hibernate.boot.registry.StandardServiceRegistry;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;
import org.hibernate.cfg.Configuration;
import org.joda.time.DateTime;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.lang.JoseException;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.ApplicationType;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.idp.providers.oidc.db.DbOidcSessionStore;
import com.tremolosecurity.idp.providers.oidc.db.StsRequest;
import com.tremolosecurity.idp.providers.oidc.model.ExpiredRefreshToken;
import com.tremolosecurity.idp.providers.oidc.model.OIDCSession;
import com.tremolosecurity.idp.providers.oidc.model.OidcSessionState;
import com.tremolosecurity.idp.providers.oidc.model.OpenIDConnectConfig;
import com.tremolosecurity.idp.providers.oidc.none.NoneBackend;
import com.tremolosecurity.idp.providers.oidc.sdk.UpdateClaims;
import com.tremolosecurity.idp.providers.oidc.session.ClearOidcSessionOnLogout;
import com.tremolosecurity.idp.providers.oidc.session.OidcSessionExpires;
import com.tremolosecurity.idp.providers.oidc.trusts.DynamicLoadTrusts;
import com.tremolosecurity.idp.providers.oidc.model.OidcSessionStore;
import com.tremolosecurity.idp.server.IDP;
import com.tremolosecurity.idp.server.IdentityProvider;
import com.tremolosecurity.json.Token;
import com.tremolosecurity.log.AccessLog;
import com.tremolosecurity.log.AccessLog.AccessEvent;
import com.tremolosecurity.openunison.OpenUnisonConstants;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.mapping.MapIdentity;
import com.tremolosecurity.proxy.SessionManagerImpl;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.auth.AzSys;
import com.tremolosecurity.proxy.auth.PostAuthSuccess;
import com.tremolosecurity.proxy.auth.RequestHolder;
import com.tremolosecurity.proxy.auth.passwordreset.PasswordResetRequest;
import com.tremolosecurity.proxy.auth.util.AuthUtil;
import com.tremolosecurity.proxy.az.AzRule;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterChainImpl;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterRequestImpl;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.filter.HttpFilterResponseImpl;
import com.tremolosecurity.proxy.filter.PostProcess;
import com.tremolosecurity.proxy.logout.LogoutUtil;
import com.tremolosecurity.proxy.util.NextSys;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.proxy.util.ProxyTools;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.server.StopableThread;

public class OpenIDConnectIdP implements IdentityProvider {

	public static final String UNISON_OPENIDCONNECT_IDPS = "unison.openidconnectidps";

	static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(OpenIDConnectIdP.class.getName());
	
	static final String TRANSACTION_DATA = "unison.openidconnect.session";

	public static final String UNISON_SESSION_OIDC_ACCESS_TOKEN = "unison.session.oidc.access.token";
	public static final String UNISON_SESSION_OIDC_ID_TOKEN = "unison.session.oidc.id.token";

	public static final String STS_TRANSACTION = "unison.session.oidc.sts.request";;
	String idpName;
	HashMap<String,OpenIDConnectTrust> trusts;
	String jwtSigningKeyName;

	OidcSessionStore sessionStore;
	
	
	private MapIdentity mapper;
	
	
	private String sessionKeyName;

	private UpdateClaims claimsUpdater;

	private HashSet<String> scopes;

	private String authURI;

	private String subAttribute;
	
	private Map<String,String> authChainToAmr;
	private Map<String,String> amrToAuthChain;
	
	int refreshTokenGracePeriodMillis;
	
	private static HashSet<String> ignoredClaims;
	
	static {
		ignoredClaims = new HashSet<String>();
		ignoredClaims.add("iss");
		ignoredClaims.add("aud");
		ignoredClaims.add("exp");
		ignoredClaims.add("jti");
		ignoredClaims.add("iat");
		ignoredClaims.add("nbf");

		
	}
	
	
	
	public void doDelete(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {


	}

	public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
		
		if (request.getHeader("Accept") != null && request.getHeader("Accept").startsWith("application/json")) {
			request.setAttribute("com.tremolosecurity.unison.proxy.noRedirectOnError", "com.tremolosecurity.unison.proxy.noRedirectOnError");
		}
		
		String action = (String) request.getAttribute(IDP.ACTION_NAME);
		
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		if (holder == null) {
			throw new ServletException("Holder is null");
		}
		
		AuthController ac = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL));
		
		
		if (action.equalsIgnoreCase(".well-known/openid-configuration")) {
			
			Gson gson = new GsonBuilder().setPrettyPrinting().create();
			String json = gson.toJson(new OpenIDConnectConfig(this.authURI,request,mapper));
			response.setContentType("application/json");
			response.getWriter().print(json);
			
			
			AccessLog.log(AccessEvent.AzSuccess, holder.getApp(), (HttpServletRequest) request, ac.getAuthInfo() , "NONE");
			
			return;
		
		} else if (action.equalsIgnoreCase("certs")) {
			try {
				X509Certificate cert = GlobalEntries.getGlobalEntries().getConfigManager().getCertificate(this.jwtSigningKeyName);
				JsonWebKey jwk = JsonWebKey.Factory.newJwk(cert.getPublicKey());
				
				
				String keyID = buildKID(cert);
				jwk.setKeyId(keyID);
				jwk.setUse("sig");
				jwk.setAlgorithm("RS256");
				response.setContentType("application/json");
				response.getWriter().print(new JsonWebKeySet(jwk).toJson());
				
				AccessLog.log(AccessEvent.AzSuccess, holder.getApp(), (HttpServletRequest) request, ac.getAuthInfo() , "NONE");
				
				return;
			} catch (JoseException e) {
				throw new ServletException("Could not generate jwt",e);
			}
		} else if (action.equalsIgnoreCase("auth")) {
			String clientID = request.getParameter("client_id");
			String responseCode = request.getParameter("response_type");
			String scope = request.getParameter("scope");
			String redirectURI = request.getParameter("redirect_uri");
			String state = request.getParameter("state");
			String nonce = request.getParameter("nonce");
			
			String codeChallenge = request.getParameter("code_challenge");
			String codeChallengeType = request.getParameter("code_challenge_method");
			
			
			
			OpenIDConnectTransaction transaction = new OpenIDConnectTransaction();
			transaction.setClientID(clientID);
			transaction.setResponseCode(responseCode);
			transaction.setNonce(nonce);
			transaction.setCodeChallenge(codeChallenge);
			transaction.setChallengeS256(codeChallengeType != null && codeChallengeType.equalsIgnoreCase("S256"));
			
			
			StringTokenizer toker = new StringTokenizer(scope," ",false);
			while (toker.hasMoreTokens()) {
				String token = toker.nextToken();
				transaction.getScope().add(token);
			}
			
			
			
			transaction.setRedirectURI(redirectURI);
			transaction.setState(state);
			
			OpenIDConnectTrust trust = trusts.get(clientID);
			
			

			if (trust == null) {
				StringBuffer b = new StringBuffer();
				b.append(redirectURI).append("?error=unauthorized_client");
				logger.warn("Trust '" + clientID + "' not found");
				response.sendRedirect(b.toString());
				return;
			}
			
			if (trust.isVerifyRedirect()) {

				if (! trust.getRedirectURI().contains	(redirectURI)) {
					StringBuffer b = new StringBuffer();
					b.append(redirectURI).append("?error=unauthorized_client");
					logger.warn("Invalid redirect");
					
					
					AccessLog.log(AccessEvent.AzFail, holder.getApp(), (HttpServletRequest) request, ac.getAuthInfo() , "NONE");
					
					response.sendRedirect(b.toString());
					return;
				}

				transaction.setRedirectURI(redirectURI);

			} else {
				transaction.setRedirectURI(redirectURI);
			}
			
			
			if (this.scopes == null) {
				if (transaction.getScope().size() == 0 || ! transaction.getScope().get(0).equals("openid")) {
					StringBuffer b = new StringBuffer();
					b.append(transaction.getRedirectURI()).append("?error=invalid_scope");
					logger.warn("First scope not openid");
					AccessLog.log(AccessEvent.AzFail, holder.getApp(), (HttpServletRequest) request, ac.getAuthInfo() , "NONE");
					response.sendRedirect(b.toString());
					return;
				} else {
					//we don't need the openid scope anymore
					transaction.getScope().remove(0);
				}
			} else {
				for (String indvScope : transaction.getScope()) {
					if (! this.scopes.contains(indvScope)) {
						StringBuffer b = new StringBuffer();
						b.append(transaction.getRedirectURI()).append("?error=invalid_scope");
						logger.warn(new StringBuilder().append("Scope '").append(indvScope).append("' not recognized"));
						AccessLog.log(AccessEvent.AzFail, holder.getApp(), (HttpServletRequest) request, ac.getAuthInfo() , "NONE");
						response.sendRedirect(b.toString());
						return;
					}
				}
			}
			
			String authChain = trust.getAuthChain();
			
			if (authChain == null) {
				StringBuffer b = new StringBuffer();
				b.append("IdP does not have an authenticaiton chain configured");
				throw new ServletException(b.toString());
			}
			
			HttpSession session = request.getSession();
			
			AuthInfo authData = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
			
			
			AuthChainType act = holder.getConfig().getAuthChains().get(authChain);
			
			session.setAttribute(OpenIDConnectIdP.TRANSACTION_DATA, transaction);
			
			if (authData == null || ! authData.isAuthComplete() && ! (authData.getAuthLevel() < act.getLevel()) ) {
				nextAuth(request,response,session,false,act);
			} else {
				if (authData.getAuthLevel() < act.getLevel()) {
					//step up authentication, clear existing auth data

					
					session.removeAttribute(ProxyConstants.AUTH_CTL);
					holder.getConfig().createAnonUser(session);
					
					nextAuth(request,response,session,false,act);
				} else {
					
					StringBuffer b = genFinalURL(request);
					response.sendRedirect(b.toString());
					
					//TODO if session already exists extend the life of the id_token
					
				}
			}
			
			
		} else if (action.contentEquals("completefed")) {
			this.completeFederation(request, response);
		} else if (action.equalsIgnoreCase("userinfo")) {
			try {
				processUserInfoRequest(request, response);
			} catch (Exception e) {
				throw new ServletException("Could not process userinfo request",e);
			}
			
		}
		

	}

	private String buildKID(X509Certificate cert) {
		StringBuffer b = new StringBuffer();
		b.append(cert.getSubjectDN().getName()).append('-').append(cert.getIssuerDN().getName()).append('-').append(cert.getSerialNumber().toString());
		return b.toString();
	}
	
	private boolean nextAuth(HttpServletRequest req,HttpServletResponse resp,HttpSession session,boolean jsRedirect,AuthChainType act) throws ServletException, IOException {
		
		RequestHolder reqHolder;
		
		UrlHolder holder = (UrlHolder) req.getAttribute(ProxyConstants.AUTOIDM_CFG);
		String urlChain = holder.getUrl().getAuthChain();
		
		if (urlChain == null) {
			//we now know which chain name it is
			holder.getUrl().setAuthChain(act.getName());
		}
		
		StringBuffer b = genFinalURL(req);
		
		
		return holder.getConfig().getAuthManager().execAuth(req, resp, session, jsRedirect, holder, act,b.toString());
	}
	
	private boolean nextTokenAuth(HttpServletRequest req,HttpServletResponse resp,HttpSession session,boolean jsRedirect,AuthChainType act) throws ServletException, IOException {
		
		RequestHolder reqHolder;
		
		UrlHolder holder = (UrlHolder) req.getAttribute(ProxyConstants.AUTOIDM_CFG);
		String urlChain = holder.getUrl().getAuthChain();
		
		if (urlChain == null) {
			//we now know which chain name it is
			holder.getUrl().setAuthChain(act.getName());
		}
		
		StringBuffer b = genTokenURL(req);
		
		
		return holder.getConfig().getAuthManager().execAuth(req, resp, session, jsRedirect, holder, act,b.toString());
	}
	
	private StringBuffer genFinalURL(HttpServletRequest req) {
		if (logger.isDebugEnabled()) {
			logger.debug("url : '" + req.getRequestURL() + "'");
		}
		
		ConfigManager cfg = (ConfigManager) req.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);
		
		String url = req.getRequestURL().substring(0,req.getRequestURL().indexOf("/",8));
		StringBuffer b = new StringBuffer(url);
		b.append(cfg.getAuthIdPPath()).append(this.idpName).append("/completefed");
		
		if (logger.isDebugEnabled()) {
			logger.debug("final url : '" + b + "'");
		}
		return b;
	}
	
	private StringBuffer genTokenURL(HttpServletRequest req) {
		if (logger.isDebugEnabled()) {
			logger.debug("url : '" + req.getRequestURL() + "'");
		}
		
		ConfigManager cfg = (ConfigManager) req.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);
		
		String url = req.getRequestURL().substring(0,req.getRequestURL().indexOf("/",8));
		StringBuffer b = new StringBuffer(url);
		b.append(cfg.getAuthIdPPath()).append(this.idpName).append("/token");
		
		if (logger.isDebugEnabled()) {
			logger.debug("token url : '" + b + "'");
		}
		return b;
	}

	public void doHead(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {


	}

	public void doOptions(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {


	}

	public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
		
		if (request.getHeader("Accept") != null && request.getHeader("Accept").startsWith("application/json")) {
			request.setAttribute("com.tremolosecurity.unison.proxy.noRedirectOnError", "com.tremolosecurity.unison.proxy.noRedirectOnError");
		}
		
		try {
		String action = (String) request.getAttribute(IDP.ACTION_NAME);
		if (action.contentEquals("completefed")) {
			this.completeFederation(request, response);
		} else if (action.equalsIgnoreCase("token")) {
			String code = request.getParameter("code");
			String clientID = request.getParameter("client_id");
			String clientSecret = request.getParameter("client_secret");
			String redirectURI = request.getParameter("redirect_uri");
			String grantType = request.getParameter("grant_type");
			String refreshToken = request.getParameter("refresh_token");
			String codeVerifier = request.getParameter("code_verifier");
			
			
			if (clientID == null) {
				
				//this means that the clientid is in the Authorization header
				String azHeader = request.getHeader("Authorization");
				
				azHeader = azHeader.substring(azHeader.indexOf(' ') + 1).trim();
				azHeader = new String(org.apache.commons.codec.binary.Base64.decodeBase64(azHeader));
				clientID = azHeader.substring(0,azHeader.indexOf(':'));
				clientSecret = azHeader.substring(azHeader.indexOf(':') + 1);
			}

			
			
			AuthController ac = (AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL);
			UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
			
			holder.getApp().getCookieConfig().getTimeout();
			
			
			
			if (refreshToken != null) {
				try {
					refreshToken(response, clientID, clientSecret, refreshToken, holder, request, ac.getAuthInfo());
				} catch (Exception e1) {
					logger.warn("Could not refresh token",e1);
					AccessLog.log(AccessEvent.AzFail, holder.getApp(), (HttpServletRequest) request, ac.getAuthInfo() ,  "NONE");
					response.sendError(401);
				} 
				
				
			} else if (grantType.equalsIgnoreCase("urn:ietf:params:oauth:grant-type:token-exchange")) {
				StsRequest stsRequest = new StsRequest();
				
				stsRequest.setAudience(request.getParameter("audience"));
				stsRequest.setDelegation(request.getParameter("actor_token") != null);
				stsRequest.setImpersonation(! stsRequest.isDelegation());
				stsRequest.setSubjectToken(request.getParameter("subject_token"));
				stsRequest.setSubjectTokenType(request.getParameter("subject_token_type"));
				stsRequest.setActorToken(request.getParameter("actor_token"));
				stsRequest.setActorTokenType(request.getParameter("actor_token_type"));
				
				
				stsRequest.setImpersonation(stsRequest.getActorToken() == null);
				stsRequest.setDelegation(stsRequest.getActorToken() != null);
				
				OpenIDConnectTrust trust = this.trusts.get(clientID);
				
				if (trust == null ) {
					String errorMessage = new StringBuilder().append("Trust '").append(clientID).append("' not found").toString();
					logger.warn(errorMessage);
					throw new Exception(errorMessage);
				}
				
				if (! trust.isSts()) {
					String errorMessage = new StringBuilder().append("Trust '").append(clientID).append("' not an sts").toString();
					logger.warn(errorMessage);
					response.sendError(401);
					return;
				}
				
				if (stsRequest.isImpersonation()) {
					stsImpersontion(request, response, clientID, ac, holder, stsRequest, trust);
				} else {
					// delegation
					
					
					if (! trust.isStsDelegation()) {
						logger.warn(new StringBuilder().append("clientid '").append(clientID).append("' does not support delegation"));
						response.sendError(403);
					}
					
					// validate the actor
					
					X509Certificate sigCert = GlobalEntries.getGlobalEntries().getConfigManager().getCertificate(this.getJwtSigningKeyName());
					
					if (sigCert == null) {
						logger.error(new StringBuilder().append("JWT Signing Certificate '").append(this.getJwtSigningKeyName()).append("' does not exist").toString());
						response.sendError(500);
						return;
					}
					
					StringBuffer issuer = new StringBuffer();
					
					
					//issuer.append(cfg.getAuthIdPPath()).append(this.idpName);
					issuer.append(holder.getApp().getUrls().getUrl().get(0).getUri());
					
					String issuerUrl = ProxyTools.getInstance().getFqdnUrl(issuer.toString(), request);
					
					
					HttpSession session = request.getSession();
					AuthInfo authData = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
					
					TokenData actorTokenData = this.validateToken(stsRequest.getActorToken(), "actor_token",sigCert.getPublicKey(), issuerUrl, clientID, holder, request, authData, response, false);
					if (actorTokenData == null) {
						return;
					}
					
					String uidAttribute = this.getUidAttributeFromMap();
					if (uidAttribute == null) {
						logger.error(new StringBuilder().append("IdP ").append(holder.getApp().getName()).append(" does not have a sub attribute mapped to a user attribute").toString());
						response.sendError(500);
						return;
					}
					
					String authChainName = null;
					AuthChainType actorAuthChain = null;
					if (actorTokenData.amr != null) {
						authChainName = this.getAmrToAuthChain().get(actorTokenData.amr);
						if (authChainName != null) {
							actorAuthChain = GlobalEntries.getGlobalEntries().getConfigManager().getAuthChains().get(authChainName);
						}
					}
					
					
					AuthInfo actorAuth = this.jwtToAuthInfo(actorTokenData, uidAttribute, actorAuthChain, authChainName);
					if (actorAuth == null) {
						//don't think this can happen
						logger.error("Could not create user auth object from jwt");
						response.sendError(500);
						return;
					}
					
					
					
					AzSys azSys = new AzSys();
					
					if (! azSys.checkRules(actorAuth, GlobalEntries.getGlobalEntries().getConfigManager(), trust.getClientAzRules(), new HashMap<String,Object>())) {
						AccessLog.log(AccessEvent.AzFail, holder.getApp(), request, actorAuth, new StringBuilder().append("client not authorized to exchange token for subject '").append(actorTokenData.subjectUid).append("'").toString());
						response.sendError(403);
						return;
					} 
					
					if (! trust.getAllowedAudiences().contains(stsRequest.getAudience())) {
						AccessLog.log(AccessEvent.AzFail, holder.getApp(), request, actorAuth, new StringBuilder().append("Audience '").append(stsRequest.getAudience()).append("' is not an authorized audience for sts '").append(trust.getTrustName()).append("'").toString());
						response.sendError(403);
						return;
					}
					
					OpenIDConnectTrust targetTrust = this.getTrusts().get(stsRequest.getAudience());
					if (targetTrust == null) {
						logger.warn(new StringBuilder().append("Audience '").append(stsRequest.getAudience()).append("' does not exist").toString());
						
						response.sendError(404);
						return;
					}
					
					
					TokenData subjectTokenData = this.validateToken(stsRequest.getSubjectToken(), "subject_token",sigCert.getPublicKey(), issuerUrl, null, holder, request, authData, response, true);
					if (subjectTokenData == null) {
						return;
					}
					
					authChainName = null;
					actorAuthChain = null;
					if (subjectTokenData.amr != null) {
						authChainName = this.getAmrToAuthChain().get(subjectTokenData.amr);
						if (authChainName != null) {
							actorAuthChain = GlobalEntries.getGlobalEntries().getConfigManager().getAuthChains().get(authChainName);
						}
					}
					
					
					AuthInfo subjectAuth = this.jwtToAuthInfo(subjectTokenData, uidAttribute, actorAuthChain, authChainName);
					if (subjectAuth == null) {
						//don't think this can happen
						logger.error("Could not create user auth object from jwt");
						response.sendError(500);
						return;
					}

					
					if (! azSys.checkRules(subjectAuth, GlobalEntries.getGlobalEntries().getConfigManager(), trust.getSubjectAzRules(), new HashMap<String,Object>())) {
						AccessLog.log(AccessEvent.AzFail, holder.getApp(), request, actorAuth, new StringBuilder().append("client not authorized to exchange token for subject '").append(subjectTokenData.subjectUid).append("'").toString());
						response.sendError(403);
						return;
					} 
					
					OpenIDConnectAccessToken access = new OpenIDConnectAccessToken();
					
					OidcSessionState oidcSession = this.createUserSession(request, stsRequest.getAudience(), holder, targetTrust, subjectAuth.getUserDN(), GlobalEntries.getGlobalEntries().getConfigManager(), access,UUID.randomUUID().toString(),subjectAuth.getAuthChain(),subjectTokenData.root,actorTokenData.root); 
					
					AccessLog.log(AccessEvent.AzSuccess, holder.getApp(), request, actorAuth, new StringBuilder().append("client '").append(trust.getTrustName()).append("' delegated to by '").append(subjectTokenData.subjectUid).append("', jti : '").append(access.getIdTokenId()).append("'").toString());
					
					
					
					String idtoken = access.getId_token();
					
					
					access.setRefresh_token(oidcSession.getRefreshToken());
					
					
					Gson gson = new Gson();
					String json = gson.toJson(access);
					
					response.setContentType("application/json");
					response.getOutputStream().write(json.getBytes("UTF-8"));
					response.getOutputStream().flush();
					
					if (logger.isDebugEnabled()) {
						logger.debug("Token JSON : '" + json + "'");
					}
				}
				
				
				
				
			} else if (grantType.equalsIgnoreCase("client_credentials")) {
				clientCredentialsGrant(request, response, clientID, clientSecret, ac, holder);
				
				
			}
			else {
				completeUserLogin(request, response, code, clientID, clientSecret, holder, ac.getAuthInfo(),codeVerifier);
			}
			
			
		} 
		} catch (Throwable t) {
			if (request.getHeader("Accept") != null && request.getHeader("Accept").startsWith("application/json")) {
				response.sendError(500);
				response.setContentType("application/json");
				response.getWriter().print("{\"error\":\"invalid_request\"}");
				logger.error("Sending JSON Error",t);
			} else {
				if (t instanceof ServletException) {
					throw (ServletException)t;
				} else if (t instanceof IOException) {
					throw (IOException)t;
				} else {
					throw new ServletException("Error processing post",t);
				}
			}
		}

	}
	
	
	
	private TokenData validateToken(String token,String tokenType,Key validationKey,String requiredIssuer,String requiredAudience, UrlHolder holder, HttpServletRequest req, AuthInfo authData, HttpServletResponse resp,boolean requiresAmr) throws ServletException {
		JsonWebSignature jws = new JsonWebSignature();
		TokenData td = new TokenData();
		try {
			jws.setCompactSerialization(token);
			jws.setKey(validationKey);
			if (! jws.verifySignature()) {
				AccessLog.log(AccessEvent.AzFail, holder.getApp(), req, authData, new StringBuilder().append("Invalid ").append(tokenType).append(" signature").toString());
				resp.sendError(403);
				return null;
			}
			
			String json = jws.getPayload();
			JSONObject obj = (JSONObject) new JSONParser().parse(json);
			td.root = obj;
			long exp = ((Long)obj.get("exp")) * 1000L;
			long nbf = ((Long)obj.get("nbf")) * 1000L;
			
			if (new DateTime(exp).isBeforeNow()) {
				AccessLog.log(AccessEvent.AzFail, holder.getApp(), req, authData, new StringBuilder().append(tokenType).append(" has expired").toString());
				resp.sendError(403);
				return null;
			}
			
			if (new DateTime(nbf).isAfterNow()) {
				AccessLog.log(AccessEvent.AzFail, holder.getApp(), req, authData, new StringBuilder().append(tokenType).append(" is not yet valid").toString());
				resp.sendError(403);
				return null;
			}
			
			StringBuffer issuer = new StringBuffer();
			
			
			//issuer.append(cfg.getAuthIdPPath()).append(this.idpName);
			issuer.append(holder.getApp().getUrls().getUrl().get(0).getUri());
			
			String issuerUrl = ProxyTools.getInstance().getFqdnUrl(issuer.toString(), req);
			
			if (! ((String) obj.get("iss")).equals(issuerUrl)) {
				AccessLog.log(AccessEvent.AzFail, holder.getApp(), req, authData, new StringBuilder().append(tokenType).append(" has an invalid issuer").toString());
				resp.sendError(403);
				return null;
			}
			
			if (requiredAudience != null) {
				if (! ((String) obj.get("aud")).equals(requiredAudience)  ) {
					AccessLog.log(AccessEvent.AzFail, holder.getApp(), req, authData, new StringBuilder().append(tokenType).append(" has an invalid audience").toString());
					resp.sendError(403);
					return null;
				}
			}
			
			td.subjectUid = (String) obj.get("sub");
			if (td.subjectUid == null) {
				logger.error("Subject has no sub claim");
				resp.sendError(422);
				return null;
			}
			
			JSONArray amrs = (JSONArray) obj.get("amr");
			if (amrs == null ) {
				if (requiresAmr) {
					logger.warn("subject_token does not contain an amr claim");
					resp.sendError(422);
					return null;
				}
			} else {
				td.amr = (String) amrs.get(0);
			}
			
			return td;
			
			
		} catch (JoseException | ParseException | IOException e) {
			throw new ServletException("Could not verify subject JWT",e);
		}
	}
	
	private AuthInfo jwtToAuthInfo(TokenData td,String uidAttr,AuthChainType act,String subjectAuthMethod) throws ServletException {
		String filter = "";
		
		
		
		
		if (td.subjectUid == null) {
			filter = "(!(objectClass=*))";
		} else {
			filter = equal(uidAttr,td.subjectUid).toString();
		}
		
		
		try {
			
			String root = act.getRoot();
			if (root == null || root.trim().isEmpty()) {
				root = GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getLdapRoot();
			}
			
			
			AuthChainType actForSubject = GlobalEntries.getGlobalEntries().getConfigManager().getAuthChains().get(subjectAuthMethod);
			if (actForSubject == null) {
				logger.warn(new StringBuilder("No authentication chain named '").append(subjectAuthMethod).append("'"));
			}
			
			LDAPSearchResults res = GlobalEntries.getGlobalEntries().getConfigManager().getMyVD().search(root, 2, filter, new ArrayList<String>());
			
			if (res.hasMore()) {
				LDAPEntry entry = res.next();
				
				
				
				AuthInfo authInfo = new AuthInfo(entry.getDN(),null,actForSubject != null ? actForSubject.getName() : null,actForSubject != null ? actForSubject.getLevel() : 0);
				User user = new User(entry);
				user = this.getMapper().mapUser(user);
				
				for (String attrName : user.getAttribs().keySet()) {
					authInfo.getAttribs().put(attrName, user.getAttribs().get(attrName));
				}
				
				if (authInfo.getAttribs().get(uidAttr) == null) {
					authInfo.getAttribs().put(uidAttr, new Attribute(uidAttr,td.subjectUid));
				}
				return authInfo;
			}  else {
				String dn = new StringBuilder().append(uidAttr).append("=").append(td.subjectUid).append(",ou=oauth2,").append(GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getLdapRoot()).toString();
				AuthInfo authInfo = new AuthInfo(dn,null,actForSubject != null ? actForSubject.getName() : null,actForSubject != null ? actForSubject.getLevel() : 0);
				
				for (Object key : td.root.keySet()) {
					Attribute attr = new Attribute(key.toString());
					
					if (attr.getName().equalsIgnoreCase("sub")) {
						authInfo.getAttribs().put(uidAttr, new Attribute(uidAttr,(String) td.root.get(key)));
					}
					
					
					if (td.root.get(key) instanceof JSONArray) {
						attr.getValues().addAll(((JSONArray)td.root.get(key)));
					} else {
						attr.getValues().add(td.root.get(key).toString());
					}
					
					authInfo.getAttribs().put((String) key, attr);
					
					return authInfo;
				}
			}
			
		} catch (LDAPException | ProvisioningException e) {
			throw new ServletException("Could not lookup sts subject",e);
		}
		return null;
	}

	private void stsImpersontion(HttpServletRequest request, HttpServletResponse response, String clientID,
			AuthController ac, UrlHolder holder, StsRequest stsRequest, OpenIDConnectTrust trust)
			throws ServletException, IOException {
		String authChain = trust.getAuthChain();
		
		if (authChain == null) {
			StringBuffer b = new StringBuffer();
			b.append("IdP does not have an authenticaiton chain configured");
			throw new ServletException(b.toString());
		}
		
		HttpSession session = request.getSession();
		
		AuthInfo authData = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
		
		
		AuthChainType act = holder.getConfig().getAuthChains().get(authChain);
		OpenIDConnectTransaction transaction = new OpenIDConnectTransaction();
		transaction.setClientID(clientID);
		session.setAttribute(OpenIDConnectIdP.TRANSACTION_DATA, transaction);
		
		
		TokenPostAuth postAuth = new TokenPostAuth(transaction,trust,stsRequest,this);
		request.setAttribute(PostAuthSuccess.POST_AUTH_ACTION, postAuth);
		
		
		
		if (authData == null || ! authData.isAuthComplete() && ! (authData.getAuthLevel() < act.getLevel()) ) {
			nextTokenAuth(request,response,session,false,act);
		} else {
			if (authData.getAuthLevel() < act.getLevel()) {
				//step up authentication, clear existing auth data

				
				session.removeAttribute(ProxyConstants.AUTH_CTL);
				holder.getConfig().createAnonUser(session);
				
				nextTokenAuth(request,response,session,false,act);
			} else {
				
				// authenticated, next step
				
				postAuth.runAfterSuccessfulAuthentication(request, response, holder, act, null, ac, null);
				
			}
		}
	}

	private void clientCredentialsGrant(HttpServletRequest request, HttpServletResponse response, String clientID,
			String clientSecret, AuthController ac, UrlHolder holder) throws Exception, IOException, ServletException {
		OpenIDConnectTrust trust = this.trusts.get(clientID);
		
		if (trust == null ) {
			String errorMessage = new StringBuilder().append("Trust '").append(clientID).append("' not found").toString();
			logger.warn(errorMessage);
			throw new Exception(errorMessage);
		}
		
		if (! trust.isEnableClientCredentialGrant()) {
			logger.error(new StringBuilder().append("Trust '").append(clientID).append("' does not support the client_credentials grant").toString());
			response.sendError(403);
			return;
		}
		
		String authChain = trust.getAuthChain();
		
		if (authChain == null) {
			
			
			
			if (trust.isPublicEndpoint()) {
				StringBuffer b = new StringBuffer();
				b.append("IdP does not have an authenticaiton chain configured, but is set to public");
				throw new ServletException(b.toString());
			} else {
				if (clientSecret == null || ! clientSecret.equals(trust.getClientSecret())) {
					logger.warn(new StringBuilder().append("Invalid client secret for '").append(clientID).append("'"));
					response.sendError(401);
					
				} else {
					HttpSession session = request.getSession();
					
					AuthInfo authData = new AuthInfo();
					authData.setUserDN(new StringBuilder().append("uid=").append(clientID).append(",ou=oauth2,").append(GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getLdapRoot()).toString());
					authData.setAuthLevel(0);
					authData.setAuthChain("anonymous");
					authData.getAttribs().put("uid", new Attribute("uid",clientID));
					authData.getAttribs().put("sub", new Attribute("sub",clientID));
					authData.getAttribs().put("client", new Attribute("client","true"));
					authData.getAttribs().put("auth_chain", new Attribute("auth_chain","anonymous"));
					authData.getAttribs().put("objectClass", new Attribute("objectClass",GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getUserObjectClass()));

					((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).setAuthInfo(authData);
					
					AuthChainType act = holder.getConfig().getAuthChains().get(authChain);
					
					OpenIDConnectTransaction transaction = new OpenIDConnectTransaction();
					transaction.setClientID(clientID);
					session.setAttribute(OpenIDConnectIdP.TRANSACTION_DATA, transaction);
					
					ClientCredentialsGrantPostAuth postAuth = new ClientCredentialsGrantPostAuth(transaction,trust,this);
					request.setAttribute(PostAuthSuccess.POST_AUTH_ACTION, postAuth);
					
					postAuth.runAfterSuccessfulAuthentication(request, response, holder, act, null, ac, null);
					
				}
				
				return;
			}
		}
		
		HttpSession session = request.getSession();
		
		AuthInfo authData = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
		
		
		AuthChainType act = holder.getConfig().getAuthChains().get(authChain);
		OpenIDConnectTransaction transaction = new OpenIDConnectTransaction();
		transaction.setClientID(clientID);
		session.setAttribute(OpenIDConnectIdP.TRANSACTION_DATA, transaction);
		
		ClientCredentialsGrantPostAuth postAuth = new ClientCredentialsGrantPostAuth(transaction,trust,this);
		request.setAttribute(PostAuthSuccess.POST_AUTH_ACTION, postAuth);
		
		
		
		if (authData == null || ! authData.isAuthComplete() && ! (authData.getAuthLevel() < act.getLevel()) ) {
			nextTokenAuth(request,response,session,false,act);
		} else {
			if (authData.getAuthLevel() < act.getLevel()) {
				//step up authentication, clear existing auth data

				
				session.removeAttribute(ProxyConstants.AUTH_CTL);
				holder.getConfig().createAnonUser(session);
				
				nextTokenAuth(request,response,session,false,act);
			} else {
				
				// authenticated, next step
				
				postAuth.runAfterSuccessfulAuthentication(request, response, holder, act, null, ac, null);
				
			}
		}
	}

	private void processUserInfoRequest(HttpServletRequest request, HttpServletResponse response)
			throws Exception {
		AuthController ac = (AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL);
		
		
		
		
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		
		holder.getApp().getCookieConfig().getTimeout();
		
		String header = request.getHeader("Authorization");
		
		if (header == null) {
			AccessLog.log(AccessEvent.AzFail, holder.getApp(), (HttpServletRequest) request, ac.getAuthInfo() ,  "NONE");
			response.sendError(401);
			return;
		}
		
		String accessToken = header.substring("Bearer ".length());
		
		OidcSessionState dbSession = this.getSessionByAccessToken(accessToken);
		if (dbSession == null) {
			AccessLog.log(AccessEvent.AzFail, holder.getApp(), (HttpServletRequest) request, ac.getAuthInfo() ,  "NONE");
			response.sendError(401);
			return;
		}
		
		
		OpenIDConnectTrust trust = trusts.get(dbSession.getClientID());
		
		JsonWebSignature jws = new JsonWebSignature();
		jws.setCompactSerialization(this.decryptToken(this.trusts.get(dbSession.getClientID()).getCodeLastmileKeyName(), new Gson(), dbSession.getEncryptedIdToken()));
		jws.setKey(GlobalEntries.getGlobalEntries().getConfigManager().getCertificate(this.jwtSigningKeyName).getPublicKey());
		
		if (! jws.verifySignature()) {
			logger.warn("id_token tampered with");
			AccessLog.log(AccessEvent.AzFail, holder.getApp(), (HttpServletRequest) request, ac.getAuthInfo() ,  "NONE");
			response.sendError(401);
			return;
		}
		
		JwtClaims claims = JwtClaims.parse(jws.getPayload());
		
		

		
		
		
		
		
		
		
		response.setContentType("application/jwt");
		String jwt = null;
		
		if (trust.isSignedUserInfo()) {
			jws = new JsonWebSignature();	
	 		jws.setPayload(claims.toJson());	
	 		jws.setKey(GlobalEntries.getGlobalEntries().getConfigManager().getPrivateKey(this.jwtSigningKeyName));	
	 		jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
	 		
			jwt = jws.getCompactSerialization();
		} else {
			jwt = claims.toJson();
		}
		
		

		response.getOutputStream().write(jwt.getBytes("UTF-8"));
		
		AuthInfo remUser = new AuthInfo();
		remUser.setUserDN(dbSession.getUserDN());
		AccessLog.log(AccessEvent.AuSuccess, holder.getApp(), (HttpServletRequest) request, remUser ,  "NONE");
		AccessLog.log(AccessEvent.AzSuccess, holder.getApp(), (HttpServletRequest) request, remUser ,  "NONE");
	}
	
	
	private void logExpiredRefreshToken(HttpServletRequest request,AuthInfo user,String msg) {
		String strevent = "ExpiredRefreshTokenUsed";
		String struser = "cn=none";
		
		if (user != null) {
			struser = user.getUserDN();
		}
		
		
		
		
		
		
		StringBuffer logLine = new StringBuffer();
		logLine.append('[').append(strevent).append("] - ");
		
		
		logLine.append(request.getRequestURL()).append(" - ");
		logLine.append(struser).append(" - ");
		logLine.append(msg);
		logLine.append(" [").append(request.getRemoteAddr()).append("] - [").append(request.getSession().getAttribute(OpenUnisonConstants.TREMOLO_SESSION_ID)).append("]");
		
		logger.info(logLine.toString());
		
		
	}

	private void refreshToken(HttpServletResponse response, String clientID, String clientSecret, String refreshToken, UrlHolder holder, HttpServletRequest request, AuthInfo authData)
			throws Exception, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException,
			JoseException, InvalidJwtException, UnsupportedEncodingException {
		Gson gson = new Gson();
		String json = this.inflate(refreshToken);
		Token token = gson.fromJson(json, Token.class);
		
		byte[] iv = org.bouncycastle.util.encoders.Base64.decode(token.getIv());
		
		
		IvParameterSpec spec =  new IvParameterSpec(iv);
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, GlobalEntries.getGlobalEntries().getConfigManager().getSecretKey(this.trusts.get(clientID).getCodeLastmileKeyName()),spec);
		
		byte[] encBytes = org.bouncycastle.util.encoders.Base64.decode(token.getEncryptedRequest());
		String decryptedRefreshToken = new String(cipher.doFinal(encBytes));
		
		OidcSessionState session = this.getSessionByRefreshToken(decryptedRefreshToken);

		if (session == null) {
			logger.warn("Session does not exist from refresh_token");
			AccessLog.log(AccessEvent.AzFail, holder.getApp(), (HttpServletRequest) request, authData ,  "NONE");
			response.sendError(401);
			return;
		}
		
		if (! session.getRefreshToken().equals(refreshToken)) {
			
			if (this.refreshTokenGracePeriodMillis > 0) {
				for (ExpiredRefreshToken expired : session.getExpiredTokens()) {
					if (expired.isStillInGracePeriod(this.refreshTokenGracePeriodMillis) && expired.getToken().equals(refreshToken)) {
						// found an expired refresh token that is still in the grace period
						// return the existing session state, unchanged
						
						OpenIDConnectAccessToken access = new OpenIDConnectAccessToken();
						
						access.setAccess_token(this.decryptToken(this.trusts.get(session.getClientID()).getCodeLastmileKeyName(), gson, session.getEncryptedAccessToken()));
						
						
						
						
						access.setExpires_in((int) (session.getExpires().getMillis() - DateTime.now().getMillis()) / 1000);
						access.setId_token(this.decryptToken(this.trusts.get(session.getClientID()).getCodeLastmileKeyName(), gson, session.getEncryptedIdToken()));
						access.setToken_type("Bearer");
						access.setRefresh_token(session.getRefreshToken());
						
						json = gson.toJson(access);
						
						response.setContentType("text/json");
						response.getOutputStream().write(json.getBytes());
						response.getOutputStream().flush();
						
						AuthInfo remUser = new AuthInfo();
						remUser.setUserDN(session.getUserDN());
						
						
						AccessLog.log(AccessEvent.AzSuccess, holder.getApp(), (HttpServletRequest) request, remUser ,  "NONE");
						this.logExpiredRefreshToken(request, remUser, "Expired token used within grace period");
						return;
					}
				}
				
				// none of the expired refresh tokens are still valid
				logger.warn("Session does not exist from refresh_token");
				AccessLog.log(AccessEvent.AzFail, holder.getApp(), (HttpServletRequest) request, authData ,  "NONE");
				response.sendError(401);
				return;
				
				
			} else {
				logger.warn("Session does not exist from refresh_token");
				AccessLog.log(AccessEvent.AzFail, holder.getApp(), (HttpServletRequest) request, authData ,  "NONE");
				response.sendError(401);
				return;
			}
			
			
		} 

		OpenIDConnectTrust trust = this.trusts.get(session.getClientID());

		if (! trust.isPublicEndpoint()) {
			if (!trust.getClientSecret().equals(clientSecret)) {
				logger.warn("Invalid client_secret");
				AccessLog.log(AccessEvent.AzFail, holder.getApp(), (HttpServletRequest) request, authData, "NONE");
				response.sendError(401);
				return;
			}
		}
		
		if (session.getExpires().isBeforeNow()) {
			logger.warn("Session expired");
			AccessLog.log(AccessEvent.AzFail, holder.getApp(), (HttpServletRequest) request, authData, "NONE");
			response.sendError(401);
			this.sessionStore.deleteSession(session.getSessionID());
			return;
		}
		
		session.getExpiredTokens().add(new ExpiredRefreshToken(session.getRefreshToken(),DateTime.now()));
		
		JsonWebSignature jws = new JsonWebSignature();
		jws.setCompactSerialization(this.decryptToken(this.trusts.get(session.getClientID()).getCodeLastmileKeyName(), gson, session.getEncryptedIdToken()));
		jws.setKey(GlobalEntries.getGlobalEntries().getConfigManager().getCertificate(this.jwtSigningKeyName).getPublicKey());
		
		if (! jws.verifySignature()) {
			logger.warn("id_token tampered with");
			AccessLog.log(AccessEvent.AzFail, holder.getApp(), (HttpServletRequest) request, authData ,  "NONE");
			response.sendError(401);
			return;
		}
		
		JwtClaims claims = JwtClaims.parse(jws.getPayload());
		
		claims.setGeneratedJwtId(); // a unique identifier for the token
		claims.setIssuedAtToNow();  // when the token was issued/created (now)
		claims.setNotBeforeMinutesInThePast(trusts.get(clientID).getAccessTokenSkewMillis() / 1000 / 60); // time before which the token is not yet valid (2 minutes ago)
		claims.setExpirationTimeMinutesInTheFuture(trusts.get(clientID).getAccessTokenTimeToLive() / 1000 / 60); // time when the token will expire (10 minutes from now)
		
		jws = new JsonWebSignature();
		jws.setPayload(claims.toJson());
		jws.setKey(GlobalEntries.getGlobalEntries().getConfigManager().getPrivateKey(this.jwtSigningKeyName));
		jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
		String newIdToken = jws.getCompactSerialization();
		session.setEncryptedIdToken(this.encryptToken( this.trusts.get(session.getClientID()).getCodeLastmileKeyName()  , gson, newIdToken));
		
		jws = new JsonWebSignature();
		jws.setKey(GlobalEntries.getGlobalEntries().getConfigManager().getCertificate(this.jwtSigningKeyName).getPublicKey());
		jws.setCompactSerialization(this.decryptToken(this.trusts.get(session.getClientID()).getCodeLastmileKeyName(), gson, session.getEncryptedAccessToken()));
		if (! jws.verifySignature()) {
			logger.warn("access_token tampered with");
			AccessLog.log(AccessEvent.AzFail, holder.getApp(), (HttpServletRequest) request, authData ,  "NONE");
			response.sendError(401);
			return;
		}
		
		claims = JwtClaims.parse(jws.getPayload());
		
		claims.setGeneratedJwtId(); // a unique identifier for the token
		claims.setIssuedAtToNow();  // when the token was issued/created (now)
		claims.setNotBeforeMinutesInThePast(trusts.get(clientID).getAccessTokenSkewMillis() / 1000 / 60); // time before which the token is not yet valid (2 minutes ago)
		claims.setExpirationTimeMinutesInTheFuture(trusts.get(clientID).getAccessTokenTimeToLive() / 1000 / 60); // time when the token will expire (10 minutes from now)
		
		jws = new JsonWebSignature();
		jws.setPayload(claims.toJson());
		jws.setKey(GlobalEntries.getGlobalEntries().getConfigManager().getPrivateKey(this.jwtSigningKeyName));
		jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
		jws.setKeyIdHeaderValue(this.buildKID(GlobalEntries.getGlobalEntries().getConfigManager().getCertificate(this.jwtSigningKeyName)));
		String newAccessToken = jws.getCompactSerialization();
		session.setEncryptedAccessToken( this.encryptToken(trust.getCodeLastmileKeyName(),gson,newAccessToken));
		
		
		
		String b64 = encryptToken(trusts.get(clientID).getCodeLastmileKeyName(), gson, session.getSessionID());
		session.setRefreshToken(b64);
		
		session.setExpires(new DateTime().plusSeconds(holder.getApp().getCookieConfig().getTimeout()));
		
		
		this.sessionStore.resetSession(session);
		
		OpenIDConnectAccessToken access = new OpenIDConnectAccessToken();
		
		access.setAccess_token(newAccessToken);
		access.setExpires_in((int) (trusts.get(clientID).getAccessTokenTimeToLive() / 1000));
		access.setId_token(newIdToken);
		access.setToken_type("Bearer");
		access.setRefresh_token(session.getRefreshToken());
		
		json = gson.toJson(access);
		
		response.setContentType("text/json");
		response.getOutputStream().write(json.getBytes());
		response.getOutputStream().flush();
		
		AuthInfo remUser = new AuthInfo();
		remUser.setUserDN(session.getUserDN());
		
		
		AccessLog.log(AccessEvent.AzSuccess, holder.getApp(), (HttpServletRequest) request, remUser ,  "NONE");
	}

	private void completeUserLogin(HttpServletRequest request, HttpServletResponse response, String code,
			String clientID, String clientSecret, UrlHolder holder, AuthInfo authData, String codeVerifier)
			throws ServletException, IOException, MalformedURLException {
		String lastMileToken = null;
		
		try {
			lastMileToken = this.inflate(code);
			lastMileToken = new String(org.bouncycastle.util.encoders.Base64.encode(lastMileToken.getBytes("UTF-8")));
		} catch (Exception e) {
			throw new ServletException("Could not inflate code",e);
		}
		
		OpenIDConnectTrust trust = this.trusts.get(clientID);

		if (! trust.isPublicEndpoint()) {
			if (!clientSecret.equals(trust.getClientSecret())) {
				AccessLog.log(AccessEvent.AzFail, holder.getApp(), (HttpServletRequest) request, authData, "NONE");
				response.sendError(403);
				return;
			}
		}
		
		ConfigManager cfg = (ConfigManager) request.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);
		
		SecretKey codeKey = cfg.getSecretKey(trust.getCodeLastmileKeyName());
		com.tremolosecurity.lastmile.LastMile lmreq = new com.tremolosecurity.lastmile.LastMile();
		try {
			lmreq.loadLastMielToken(lastMileToken, codeKey);
		} catch (Exception e) {
			logger.warn("Could not decrypt code token",e);
			response.sendError(403);
			AccessLog.log(AccessEvent.AzFail, holder.getApp(), (HttpServletRequest) request, authData ,  "NONE");
			return;
		}
		
		if (! lmreq.isValid()) {
			
			response.sendError(403);
			logger.warn("Could not validate code token");
			AccessLog.log(AccessEvent.AzFail, holder.getApp(), (HttpServletRequest) request, authData ,  "NONE");
			return;
		}
		
		Attribute dn = null;
		Attribute scopes = null;
		Attribute nonce = null;
		Attribute authChainName = null;
		
		Attribute codeVerifierAttr = null;
		Attribute codeVerifierS256 = null;
		
		for (Attribute attr : lmreq.getAttributes()) {
			if (attr.getName().equalsIgnoreCase("dn")) {
				dn = attr;
			} else if (attr.getName().equalsIgnoreCase("scope")) {
				scopes = attr;
			} else if (attr.getName().equalsIgnoreCase("nonce")) {
				nonce = attr;
			} else if (attr.getName().equalsIgnoreCase("authChainName")) {
				authChainName = attr;
			} else if (attr.getName().equalsIgnoreCase("codeChallenge")) {
				codeVerifierAttr = attr;
			} else if (attr.getName().equalsIgnoreCase("codeChallengeS256")) {
				codeVerifierS256 = attr;
			}
		}
		
		if (codeVerifierAttr != null) {
			// need to run a code verifier
			if (codeVerifier == null) {
				response.sendError(400);
				logger.warn("No code_verifier parameter in the token request");
				AccessLog.log(AccessEvent.AzFail, holder.getApp(), (HttpServletRequest) request, authData ,  "NONE");
				return;
			}
			
			if (codeVerifierS256 != null && codeVerifierS256.getValues().get(0).equals("false")) {
				// plain, ew
				if (! codeVerifierAttr.getValues().get(0).equals(codeVerifier)) {
					response.sendError(400);
					logger.warn("code_verifier parameter does not match from transaction, plain");
					AccessLog.log(AccessEvent.AzFail, holder.getApp(), (HttpServletRequest) request, authData ,  "NONE");
					return;
				}
			} else {
				MessageDigest digest;
				try {
					digest = MessageDigest.getInstance("SHA-256");
				} catch (NoSuchAlgorithmException e) {
					throw new IOException("Could not generate code verifier",e);
				}
				byte[] encodedhash = digest.digest(codeVerifier.getBytes(StandardCharsets.UTF_8));
				String s256CodeVerifier = new String(org.apache.commons.codec.binary.Base64.encodeBase64URLSafe(encodedhash));
				
				if (! s256CodeVerifier.equals(codeVerifierAttr.getValues().get(0)) ) {
					response.sendError(400);
					logger.warn("code_verifier parameter does not match from transaction, S256");
					AccessLog.log(AccessEvent.AzFail, holder.getApp(), (HttpServletRequest) request, authData ,  "NONE");
					return;
				}
					 
			}
		}
		
		
		ConfigManager cfgMgr = (ConfigManager) request.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);
		
		DateTime now = new DateTime();
		DateTime notBefore = now.minus(trust.getCodeTokenTimeToLive());
		DateTime notAfter = now.plus(trust.getCodeTokenTimeToLive());
		
		int authLevel = lmreq.getLoginLevel();
		String authMethod = lmreq.getAuthChain();
		
		try {
			lmreq = new com.tremolosecurity.lastmile.LastMile(request.getRequestURI(),notBefore,notAfter,authLevel,authMethod);
		} catch (URISyntaxException e) {
			throw new ServletException("Could not request access token",e);
		}
		
		OpenIDConnectAccessToken access = new OpenIDConnectAccessToken();
		
		/*
		lmreq.getAttributes().add(new Attribute("dn",dn.getValues().get(0)));
		SecretKey key = cfgMgr.getSecretKey(trust.getAccessLastmileKeyName());
		String accessToken = null;
		try {
			accessToken = lmreq.generateLastMileToken(key);
		} catch (Exception e) {
			throw new ServletException("Could not generate access token",e);
		}*/
		
		String accessToken = null;
		
		OidcSessionState oidcSession = createUserSession(request, clientID, holder, trust, dn.getValues().get(0), cfgMgr, access,(nonce != null ? nonce.getValues().get(0) : UUID.randomUUID().toString()),authChainName.getValues().get(0)); 
		
		
		
		
		
		
		
		access.setRefresh_token(oidcSession.getRefreshToken());
		
		
		Gson gson = new Gson();
		String json = gson.toJson(access);
		
		response.setContentType("application/json");
		response.getOutputStream().write(json.getBytes("UTF-8"));
		response.getOutputStream().flush();
		
		if (logger.isDebugEnabled()) {
			logger.debug("Token JSON : '" + json + "'");
		}
		
		
		AuthInfo remUser = new AuthInfo();
		remUser.setUserDN(dn.getValues().get(0));
		
		
		request.getSession().setAttribute(new StringBuilder().append("OIDC_SESSION_ID_").append(this.idpName).toString(), oidcSession.getSessionID());
		
		AccessLog.log(AccessEvent.AzSuccess, holder.getApp(), (HttpServletRequest) request, remUser ,  "NONE");
	}

	public OidcSessionState createUserSession(HttpServletRequest request, String clientID, UrlHolder holder,
			OpenIDConnectTrust trust, String dn,  ConfigManager cfgMgr, OpenIDConnectAccessToken access,String nonce,String authChain)
			throws UnsupportedEncodingException, IOException, ServletException, MalformedURLException {
		return this.createUserSession(request, clientID, holder, trust, dn, cfgMgr, access, nonce, authChain, null,null);
	}
	
	public OidcSessionState createUserSession(HttpServletRequest request, String clientID, UrlHolder holder,
			OpenIDConnectTrust trust, String dn,  ConfigManager cfgMgr, OpenIDConnectAccessToken access,String nonce,String authChain, JSONObject existingClaims,JSONObject actor)
			throws UnsupportedEncodingException, IOException, ServletException, MalformedURLException {
		
		
		
		String sessionID = UUID.randomUUID().toString();
		String encryptedSessionID = null;
		
		try {
			encryptedSessionID = this.encryptToken(this.sessionKeyName, new Gson(), sessionID);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException e2) {
			throw new ServletException("Could not generate session id",e2);
		}
		
		
		HashMap<String,String> extraAttribs = new HashMap<String,String>();
		extraAttribs.put("session_id", encryptedSessionID);
		String accessToken = null;
		try {
			accessToken = this.produceJWT(this.generateClaims(dn,  cfgMgr, new URL(request.getRequestURL().toString()), trust,nonce,extraAttribs,request,authChain,existingClaims,actor),cfgMgr).getCompactSerialization();
		} catch (JoseException | LDAPException | ProvisioningException e1) {
			throw new ServletException("Could not generate jwt",e1);
		} 
		
		
		
		
		
		
		
		
		access.setAccess_token(accessToken);
		access.setExpires_in((int) (trust.getAccessTokenTimeToLive() / 1000));
		try {
			JwtClaims claims = this.generateClaims(dn,  cfgMgr, new URL(request.getRequestURL().toString()), trust,nonce,null,request,authChain,existingClaims,actor);
			access.setIdTokenId(claims.getJwtId());
			access.setId_token(this.produceJWT(claims,cfgMgr).getCompactSerialization());
		} catch (Exception e) {
			throw new ServletException("Could not generate JWT",e);
		} 
		
		access.setToken_type("Bearer");
		OidcSessionState oidcSession = null;
		
		try {			
			oidcSession = this.storeSession(access, holder.getApp(), trust.getCodeLastmileKeyName(), clientID,dn,sessionID);
			if (! (this.sessionStore instanceof NoneBackend)) {
				request.getSession().setAttribute(SessionManagerImpl.TREMOLO_EXTERNAL_SESSION, new OidcSessionExpires(oidcSession.getSessionID(),this.sessionStore));
			}
		} catch (Exception e) {
			throw new ServletException("Could not store session",e);
		}
		
		
		LogoutUtil.insertFirstLogoutHandler(request, new ClearOidcSessionOnLogout(oidcSession,this));
		
		return oidcSession;
	}
	
	public OidcSessionState storeSession(OpenIDConnectAccessToken access,ApplicationType app,String codeTokenKeyName,String clientID, String userDN, String sessionID) throws Exception {
		Gson gson = new Gson();
		OidcSessionState sessionState = new OidcSessionState();
		sessionState.setSessionID(sessionID);
		sessionState.setEncryptedIdToken(encryptToken(codeTokenKeyName, gson, access.getId_token()));
		sessionState.setEncryptedAccessToken(encryptToken(codeTokenKeyName, gson, access.getAccess_token()));
		sessionState.setExpires(new DateTime().plusSeconds(app.getCookieConfig().getTimeout()));
		sessionState.setUserDN(userDN);
		sessionState.setRefreshToken(this.encryptToken(codeTokenKeyName, gson, sessionID));
		sessionState.setClientID(clientID);
		this.sessionStore.saveUserSession(sessionState);
		return sessionState;
		
	}

	/*public OIDCSession storeSession(OpenIDConnectAccessToken access,ApplicationType app,String codeTokenKeyName,HttpServletRequest request,String userDN,String clientID) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
		Gson gson = new Gson();
		
		OIDCSession session = new OIDCSession();
		session.setAccessToken(access.getAccess_token());
		session.setIdToken(access.getId_token());
		session.setApplicationName(app.getName());
		session.setSessionExpires(new Timestamp(new DateTime().plusSeconds(app.getCookieConfig().getTimeout()).getMillis()));
		session.setUserDN(userDN);
		session.setClientID(clientID);
		UUID refreshToken = UUID.randomUUID();

		
		session.setRefreshToken(refreshToken.toString());
		
		String b64 = encryptToken(codeTokenKeyName, gson, refreshToken);
		
		
		session.setEncryptedRefreshToken(b64);

		Session db = null;
		try {
			db = this.sessionFactory.openSession();
			
			db.beginTransaction();
			db.save(session);
			db.getTransaction().commit();
			
			
			LogoutUtil.insertFirstLogoutHandler(request, new ClearOidcSessionOnLogout(session,this));
			
			
			return session;
			
		} finally {
			if (db != null) {
				if (db.getTransaction() != null && db.getTransaction().isActive()) {
					db.getTransaction().rollback();
				}
				db.close();
			}
		}
		
	}*/

	
	private String decryptToken(String codeTokenKeyName, Gson gson, String encrypted) throws Exception {
		String inflated = this.inflate(encrypted);
		Token token = gson.fromJson(inflated, Token.class);
		
		byte[] iv = org.bouncycastle.util.encoders.Base64.decode(token.getIv());
		IvParameterSpec spec =  new IvParameterSpec(iv);
		
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, GlobalEntries.getGlobalEntries().getConfigManager().getSecretKey(codeTokenKeyName),spec);
		
		byte[] decBytes = org.bouncycastle.util.encoders.Base64.decode(token.getEncryptedRequest());
		
		return new String(cipher.doFinal(decBytes));
	}
	
	private String encryptToken(String codeTokenKeyName, Gson gson, String data)
			throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException, IOException {
		byte[] bjson = data.getBytes("UTF-8");
		
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, GlobalEntries.getGlobalEntries().getConfigManager().getSecretKey(codeTokenKeyName));
		
		byte[] encJson = cipher.doFinal(bjson);
		String base64d = new String(org.bouncycastle.util.encoders.Base64.encode(encJson));
		
		Token token = new Token();
		token.setEncryptedRequest(base64d);
		token.setIv(new String(org.bouncycastle.util.encoders.Base64.encode(cipher.getIV())));
		
		
		byte[] bxml = gson.toJson(token).getBytes("UTF-8");

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		
		DeflaterOutputStream compressor  = new DeflaterOutputStream(baos,new Deflater(Deflater.BEST_COMPRESSION,true));
		
		compressor.write(bxml);
		compressor.flush();
		compressor.close();
		
		
		
		String b64 = new String( org.bouncycastle.util.encoders.Base64.encode(baos.toByteArray()));
		return b64;
	}
	
	private String encryptToken(String codeTokenKeyName, Gson gson, UUID refreshToken)
			throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException, IOException {
		byte[] bjson = refreshToken.toString().getBytes("UTF-8");
		
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, GlobalEntries.getGlobalEntries().getConfigManager().getSecretKey(codeTokenKeyName));
		
		byte[] encJson = cipher.doFinal(bjson);
		String base64d = new String(org.bouncycastle.util.encoders.Base64.encode(encJson));
		
		Token token = new Token();
		token.setEncryptedRequest(base64d);
		token.setIv(new String(org.bouncycastle.util.encoders.Base64.encode(cipher.getIV())));
		
		
		byte[] bxml = gson.toJson(token).getBytes("UTF-8");

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		
		DeflaterOutputStream compressor  = new DeflaterOutputStream(baos,new Deflater(Deflater.BEST_COMPRESSION,true));
		
		compressor.write(bxml);
		compressor.flush();
		compressor.close();
		
		
		
		String b64 = new String( org.bouncycastle.util.encoders.Base64.encode(baos.toByteArray()));
		return b64;
	}

	private String inflate(String saml) throws Exception {
		byte[] compressedData = org.bouncycastle.util.encoders.Base64.decode(saml);
		ByteArrayInputStream bin = new ByteArrayInputStream(compressedData);
		
		InflaterInputStream decompressor  = new InflaterInputStream(bin,new Inflater(true));
		//decompressor.setInput(compressedData);
		
		// Create an expandable byte array to hold the decompressed data
		ByteArrayOutputStream bos = new ByteArrayOutputStream(compressedData.length);
		
		// Decompress the data
		byte[] buf = new byte[1024];
		int len;
		while ((len = decompressor.read(buf)) > 0) {
		    
		        
		        bos.write(buf, 0, len);
		    
		}
		try {
		    bos.close();
		} catch (IOException e) {
		}

		// Get the decompressed data
		byte[] decompressedData = bos.toByteArray();
		
		String decoded = new String(decompressedData);
		
		return decoded;
	}
	
	public void doPut(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
	

	}

	
	private void completeFederation(HttpServletRequest request,
			HttpServletResponse response) throws IOException, ServletException,
			MalformedURLException {
		
		
		final OpenIDConnectTransaction transaction = (OpenIDConnectTransaction) request.getSession().getAttribute(OpenIDConnectIdP.TRANSACTION_DATA);
		
		
		final AuthInfo authInfo = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
		
		
		
		if (! authInfo.isAuthComplete()) {
			logger.warn("Attempted completetd federation before autthentication is completeed, clearing authentication and redirecting to the original URL");
			
			UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
			request.getSession().removeAttribute(ProxyConstants.AUTH_CTL);
			holder.getConfig().createAnonUser(request.getSession());
			StringBuffer b = new StringBuffer();
			b.append(transaction.getRedirectURI()).append("?error=login_reset");
			response.sendRedirect(b.toString());
			return;
		}
		
		
		request.setAttribute(AzSys.FORCE, "true");
		NextSys completeFed = new NextSys() {

			
			public void nextSys(final HttpServletRequest request,
					final HttpServletResponse response) throws IOException,
					ServletException {
				
				
				
				
				
				UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
				
				HttpFilterRequest filterReq = new HttpFilterRequestImpl(request, null);
				HttpFilterResponse filterResp = new HttpFilterResponseImpl(response);

				PostProcess postProc = new PostProcess() {

					@Override
					public void postProcess(HttpFilterRequest req,
							HttpFilterResponse resp, UrlHolder holder,HttpFilterChain chain)
							throws Exception {
						postResponse(transaction, request, response, authInfo,
								holder);
						
					}

					

					@Override
					public boolean addHeader(String name) {
						
						return false;
					}
					
				};
				
				HttpFilterChain chain = new HttpFilterChainImpl(holder,postProc);
				try {
					chain.nextFilter(filterReq, filterResp, chain);
				} catch (Exception e) {
					
					throw new ServletException(e);
				}
				
				
				
				
			}
			
		};
		
		AzSys az = new AzSys();
		az.doAz(request, response, completeFed);
	}
	
	private void postResponse(OpenIDConnectTransaction transaction, HttpServletRequest request,
			HttpServletResponse response, AuthInfo authInfo, UrlHolder holder) throws Exception {
		//first generate a lastmile token
		OpenIDConnectTrust trust = trusts.get(transaction.getClientID());
		
		ConfigManager cfgMgr = (ConfigManager) request.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);
		
		DateTime now = new DateTime();
		DateTime notBefore = now.minus(trust.getCodeTokenTimeToLive());
		DateTime notAfter = now.plus(trust.getCodeTokenTimeToLive());
		
		com.tremolosecurity.lastmile.LastMile lmreq = new com.tremolosecurity.lastmile.LastMile(request.getRequestURI(),notBefore,notAfter,authInfo.getAuthLevel(),authInfo.getAuthMethod());
		lmreq.getAttributes().add(new Attribute("dn",authInfo.getUserDN()));
		Attribute attr = new Attribute("scope");
		attr.getValues().addAll(transaction.getScope());
		lmreq.getAttributes().add(attr);
		if (transaction.getNonce() != null) {
			lmreq.getAttributes().add(new Attribute("nonce",transaction.getNonce()));
		}
		lmreq.getAttributes().add(new Attribute("authChainName",authInfo.getAuthChain()));
		
		if (transaction.getCodeChallenge() != null) {
			lmreq.getAttributes().add(new Attribute("codeChallenge",transaction.getCodeChallenge()));
			lmreq.getAttributes().add(new Attribute("codeChallengeS256",transaction.isChallengeS256() ? "true" : "false"));			
		}
		
		SecretKey key = cfgMgr.getSecretKey(trust.getCodeLastmileKeyName());
		
		String codeToken = lmreq.generateLastMileToken(key);
		
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		
		DeflaterOutputStream compressor  = new DeflaterOutputStream(baos,new Deflater(Deflater.BEST_COMPRESSION,true));
		
		compressor.write(org.bouncycastle.util.encoders.Base64.decode(codeToken.getBytes("UTF-8")));
		compressor.flush();
		compressor.close();
		
		
		
		String b64 = new String( org.bouncycastle.util.encoders.Base64.encode(baos.toByteArray()));
		
		
		StringBuffer b = new StringBuffer();
		b.append(transaction.getRedirectURI())
			.append("?")
			.append("code=").append(URLEncoder.encode(b64,"UTF-8"))
			.append("&state=").append(URLEncoder.encode(transaction.getState(),"UTF-8"));
		
		response.sendRedirect(b.toString());
		
	}
	
	public void init(String idpName,ServletContext ctx, HashMap<String, Attribute> init,
			HashMap<String, HashMap<String, Attribute>> trustCfg,MapIdentity mapper) {
		final String localIdPName = idpName;
		this.idpName = idpName;
		
		if (init.containsKey("refreshTokenGraceMillis")) {
			this.refreshTokenGracePeriodMillis = Integer.parseInt(init.get("refreshTokenGraceMillis").getValues().get(0));
		} else {
			this.refreshTokenGracePeriodMillis = 0;
		}
		
		this.authURI = GlobalEntries.getGlobalEntries().getConfigManager().getApp(this.idpName).getUrls().getUrl().get(0).getUri();
		
		try {
			loadStaticTrusts(trustCfg);
		} catch (Exception e1) {
			logger.warn("could not load trusts",e1);
		}
		
		if (init.get("trustConfigurationClassName") != null) {
			String className = init.get("trustConfigurationClassName").getValues().get(0);
			DynamicLoadTrusts loadTrusts;
			try {
				loadTrusts = (DynamicLoadTrusts) Class.forName(className).newInstance();
				
				
				
				loadTrusts.loadTrusts(idpName, ctx, init, trustCfg, mapper,this.trusts);
				
			} catch (Exception e) {
				logger.error("Could not initialize trusts",e);
			}
			
		} 
			
		
		
		this.amrToAuthChain = new HashMap<String,String>();
		this.authChainToAmr = new HashMap<String,String>();
		
		Attribute au2Amr = init.get("authChainToAmr");
		
		if (au2Amr != null) {
			for (String val : au2Amr.getValues()) {
				String au = val.substring(0,val.indexOf('='));
				String amr = val.substring(val.indexOf('=') + 1);
				
				this.authChainToAmr.put(au, amr);
				this.amrToAuthChain.put(amr, au);
			}
		}
		
		
		
		this.mapper = mapper;
		
		this.subAttribute = mapper.getSourceAttributeName("sub");
		
		
		this.jwtSigningKeyName = init.get("jwtSigningKey").getValues().get(0);
		
		HashMap<String,OpenIDConnectIdP> oidcIdPs = (HashMap<String, OpenIDConnectIdP>) GlobalEntries.getGlobalEntries().get(UNISON_OPENIDCONNECT_IDPS);
		if (oidcIdPs == null) {
			oidcIdPs = new HashMap<String,OpenIDConnectIdP>();
			GlobalEntries.getGlobalEntries().set(UNISON_OPENIDCONNECT_IDPS, oidcIdPs);
		}
		
		oidcIdPs.put(this.idpName, this);
		
		GlobalEntries.getGlobalEntries().getConfigManager().addThread(new StopableThread() {

			@Override
			public void run() {
				//do nothing
				
			}

			@Override
			public void stop() {
				HashMap<String,OpenIDConnectIdP> oidcIdPs = (HashMap<String, OpenIDConnectIdP>) GlobalEntries.getGlobalEntries().get(UNISON_OPENIDCONNECT_IDPS);
				if (oidcIdPs != null) {
					OpenIDConnectIdP me = oidcIdPs.remove(localIdPName);
					try {
						me.getSessionStore().shutdown();
					} catch (Exception e) {
						logger.error("Could not shutdown session store",e);
					}
				}
				
			}});
		
		
        String sessionStoreClassName = init.get("sessionStoreClassName") != null ? init.get("sessionStoreClassName").getValues().get(0) : "com.tremolosecurity.idp.providers.oidc.db.DbOidcSessionStore";
        
        try {
        	this.sessionStore = (OidcSessionStore) Class.forName(sessionStoreClassName).newInstance();
			this.sessionStore.init(localIdPName, ctx, init, trustCfg, mapper);
		} catch (Exception e) {
			logger.error("Could not initialize session store",e);
		}
        
        this.sessionKeyName = GlobalEntries.getGlobalEntries().getConfigManager().getApp(this.idpName).getCookieConfig().getKeyAlias();
        
        if (init.get("updateClaimsClassName") != null) {
        	try {
				this.claimsUpdater = (UpdateClaims) Class.forName(init.get("updateClaimsClassName").getValues().get(0)).newInstance();
			} catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
				logger.error("Could not initialize claim updater", e);
			}
        }
        
        if (init.get("scopes") != null) {
        	this.scopes = new HashSet<String>();
        	this.scopes.addAll(init.get("scopes").getValues());
        }

	}

	private void loadStaticTrusts(HashMap<String, HashMap<String, Attribute>> trustCfg) throws Exception {
		this.trusts = new HashMap<String,OpenIDConnectTrust>();
		for (String trustName : trustCfg.keySet()) {
			HashMap<String,Attribute> attrs = trustCfg.get(trustName);
			OpenIDConnectTrust trust = new OpenIDConnectTrust();
			trust.setClientID(attrs.get("clientID").getValues().get(0));
			trust.setClientSecret(attrs.get("clientSecret").getValues().get(0));
			
			trust.getRedirectURI().addAll(attrs.get("redirectURI").getValues());
			
			
			trust.setCodeLastmileKeyName(attrs.get("codeLastMileKeyName").getValues().get(0));
			trust.setAuthChain(attrs.get("authChainName") != null ? attrs.get("authChainName").getValues().get(0) : null);
			trust.setCodeTokenTimeToLive(Long.parseLong(attrs.get("codeTokenSkewMilis").getValues().get(0)));
			trust.setAccessTokenTimeToLive(Long.parseLong(attrs.get("accessTokenTimeToLive").getValues().get(0)));
			trust.setAccessTokenSkewMillis(Long.parseLong(attrs.get("accessTokenSkewMillis").getValues().get(0)));

			
			trust.setSignedUserInfo(attrs.get("signedUserInfo") != null && attrs.get("signedUserInfo").getValues().get(0).equalsIgnoreCase("true"));
			
			Attribute clientAzRuleCfg = attrs.get("clientAzRules");
			if (clientAzRuleCfg != null) {
				for (String ruleCfg : clientAzRuleCfg.getValues()) {
					
					StringTokenizer toker = new StringTokenizer(ruleCfg,";",false);
					toker.hasMoreTokens();
					String scope = toker.nextToken();
					toker.hasMoreTokens();
					String constraint = toker.nextToken();
					
					try {
						AzRule rule = new AzRule(scope,constraint,null,GlobalEntries.getGlobalEntries().getConfigManager(),null);
						trust.getClientAzRules().add(rule);
					} catch (ProvisioningException e) {
						throw new ServletException("Could not create az rule",e);
					}
				}
			}
			
			
			
			
			trust.setSts(attrs.get("isSts") != null && attrs.get("isSts").getValues().get(0).equalsIgnoreCase("true"));
			if (trust.isSts()) {
				
				
				Attribute allowedAudiences = attrs.get("authorizedAudiences");
				if (allowedAudiences != null) {
					trust.getAllowedAudiences().addAll(allowedAudiences.getValues());
				}
				
				Attribute subjectAzRuleCfg = attrs.get("subjectAzRules");
				if (subjectAzRuleCfg != null) {
					for (String ruleCfg : subjectAzRuleCfg.getValues()) {
						
						StringTokenizer toker = new StringTokenizer(ruleCfg,";",false);
						toker.hasMoreTokens();
						String scope = toker.nextToken();
						toker.hasMoreTokens();
						String constraint = toker.nextToken();
						
						try {
							AzRule rule = new AzRule(scope,constraint,null,GlobalEntries.getGlobalEntries().getConfigManager(),null);
							trust.getSubjectAzRules().add(rule);
						} catch (ProvisioningException e) {
							throw new ServletException("Could not create az rule",e);
						}
					}
				}
				
				trust.setStsImpersonation(attrs.get("stsImpersonation") != null && attrs.get("stsImpersonation").getValues().get(0).equalsIgnoreCase("true"));
				trust.setStsDelegation(attrs.get("stsDelegation") != null && attrs.get("stsDelegation").getValues().get(0).equalsIgnoreCase("true"));
				
			}
			Attribute enableClientCredentialsGrant = attrs.get("enableClientCredentialsGrant");
			if (enableClientCredentialsGrant != null) {
				trust.setEnableClientCredentialGrant(enableClientCredentialsGrant.getValues().get(0).equalsIgnoreCase("true"));
			}
			
			
			
			
			
			
			
			
			
			
			
			
			
			if (attrs.get("verifyRedirect") == null) {
				trust.setVerifyRedirect(true);
			} else {
				trust.setVerifyRedirect(attrs.get("verifyRedirect").getValues().get(0).equalsIgnoreCase("true"));
			}

			trust.setTrustName(trustName);

			if (attrs.get("publicEndpoint") != null && attrs.get("publicEndpoint").getValues().get(0).equalsIgnoreCase("true")) {
				trust.setPublicEndpoint(true);
			}

			trusts.put(trust.getClientID(), trust);
			
		}
	}

	public OidcSessionStore getSessionStore() {
		return this.sessionStore;
	}

	public JsonWebSignature generateJWS(JwtClaims claims) throws JoseException, LDAPException, ProvisioningException, MalformedURLException {
		
		
		return this.produceJWT(claims,GlobalEntries.getGlobalEntries().getConfigManager());
	}
	
	
	public JwtClaims generateClaims(AuthInfo user,ConfigManager cfg,String trustName,String urlOfRequest,HttpServletRequest request) throws JoseException, LDAPException, ProvisioningException, MalformedURLException {
		String url = urlOfRequest;
		int end = url.indexOf('/',url.indexOf("://") + 3);
		if (end != -1) {
			url = url.substring(0,end);
		}
		
		return generateClaims(user.getUserDN(), cfg, new URL(url), this.trusts.get(trustName), null,null,request,user.getAuthChain());
	}
	
	
	private JsonWebSignature produceJWT(JwtClaims claims,ConfigManager cfg) throws JoseException, LDAPException, ProvisioningException {
		//String dn,ConfigManager cfg,URL url,OpenIDConnectTrust trust,HttpServletRequest request,String nonce
		//JwtClaims claims = generateClaims(dn, cfg, url, trust, nonce);
	    
	   

	    // A JWT is a JWS and/or a JWE with JSON claims as the payload.
	    // In this example it is a JWS so we create a JsonWebSignature object.
	    JsonWebSignature jws = new JsonWebSignature();

	    // The payload of the JWS is JSON content of the JWT Claims
	    jws.setPayload(claims.toJson());

	    // The JWT is signed using the private key
	    jws.setKey(cfg.getPrivateKey(this.jwtSigningKeyName));

	    // Set the Key ID (kid) header because it's just the polite thing to do.
	    // We only have one key in this example but a using a Key ID helps
	    // facilitate a smooth key rollover process
	    //jws.setKeyIdHeaderValue(javax.xml.bind.DatatypeConverter.printHexBinary(cfg.getCertificate(jwtSigningKeyName).getExtensionValue("2.5.29.14")));

	    jws.setKeyIdHeaderValue(this.buildKID(cfg.getCertificate(this.jwtSigningKeyName)));
	    
	    
	    // Set the signature algorithm on the JWT/JWS that will integrity protect the claims
	    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
	    

	    
	    
	    return jws;
	}

	private JwtClaims generateClaims(String dn, ConfigManager cfg, URL url, OpenIDConnectTrust trust, String nonce, HashMap<String, String> extraAttribs,HttpServletRequest request,String authChainName) throws LDAPException, ProvisioningException {
		return this.generateClaims(dn, cfg, url, trust, nonce, extraAttribs, request, authChainName,null,null);
	}
	
	private JwtClaims generateClaims(String dn, ConfigManager cfg, URL url, OpenIDConnectTrust trust, String nonce, HashMap<String, String> extraAttribs,HttpServletRequest request,String authChainName,JSONObject existingClaims,JSONObject actor)
			throws LDAPException, ProvisioningException {
		StringBuffer issuer = new StringBuffer();
		
	
		//issuer.append(cfg.getAuthIdPPath()).append(this.idpName);
		issuer.append(this.authURI);
		
		String issuerUrl = ProxyTools.getInstance().getFqdnUrl(issuer.toString(), request);
		
		
		// Create the Claims, which will be the content of the JWT
	    JwtClaims claims = new JwtClaims();
	    claims.setIssuer(issuerUrl);  // who creates the token and signs it
	    claims.setAudience(trust.getClientID()); // to whom the token is intended to be sent
	    claims.setExpirationTimeMinutesInTheFuture(trust.getAccessTokenTimeToLive() / 1000 / 60); // time when the token will expire (10 minutes from now)
	    
	    claims.setGeneratedJwtId(); // a unique identifier for the token
	    claims.setIssuedAtToNow();  // when the token was issued/created (now)
	    claims.setNotBeforeMinutesInThePast(trust.getAccessTokenSkewMillis() / 1000 / 60); // time before which the token is not yet valid (2 minutes ago)
	    //claims.setSubject(dn); // the subject/principal is whom the token is about
	    if (nonce != null) {
	    	claims.setClaim("nonce", nonce);
	    }
	    
	    
	    
	    LDAPEntry entry = null;
	    User user = null;
	    
	    ArrayList<String> attrs = new ArrayList<String>();
	    
	    	
	    	LDAPSearchResults res = null;
	    	boolean userFromLdap = false;
	    	try {
	    		res = cfg.getMyVD().search(dn,0, "(objectClass=*)", attrs);
	    		if (res.hasMore()) {
	    			userFromLdap = true;
	    		}
	    	} catch (LDAPException e) {
	    		if (e.getResultCode() == 32) {
	    			userFromLdap = false;
	    		} else {
	    			throw e;
	    		}
	    	}
	    	
	    	
	    	if (userFromLdap) {
	    		entry = res.next();
	    	} else {
			    if (existingClaims != null) {
			    	LDAPAttributeSet atts = new LDAPAttributeSet();
			    	
			    	for (Object key : existingClaims.keySet()) {
			    		if (! ignoredClaims.contains((String) key)) {
			    			LDAPAttribute attr = new LDAPAttribute((String)key);
			    			atts.add(attr);
			    			Object o = existingClaims.get(key);
			    			if (o instanceof JSONArray) {
			    				JSONArray vals = (JSONArray) o;
			    				for (Object x : vals) {
			    					try {
										attr.addValue(x.toString().getBytes("UTF-8"));
									} catch (UnsupportedEncodingException e) {
										//can't happen
									}
			    				}
			    			} else {
			    				try {
									attr.addValue(o.toString().getBytes("UTF-8"));
								} catch (UnsupportedEncodingException e) {
									//can't happen
								}
			    			}
			    		}
			    	}
			    	
			    	entry = new LDAPEntry(dn,atts);
			    	
			    } else {
			    	throw new ProvisioningException("Could not lookup user or get from existing claims");
			    }
	    	}
	    	
	    	
		    
		    user = new User(entry); 
		    
		    if (userFromLdap) {
		    	user = this.mapper.mapUser(user, true);
		    } 
		    
		    
		    
		    for (String attrName : user.getAttribs().keySet()) {
		    	Attribute attr = user.getAttribs().get(attrName);
		    	if (attr != null) {
			    	if (attr.getName().equalsIgnoreCase("sub")) {
			    		claims.setSubject(attr.getValues().get(0));
			    	} else if (attr.getValues().size() == 1) {
			    		claims.setClaim(attrName,attr.getValues().get(0));
			    	} else {
			    		claims.setStringListClaim(attrName, attr.getValues());
			    	}
		    	}
		    }
	    
	    
	    String amr = this.authChainToAmr.get(authChainName);
	    if (amr != null) {
	    	claims.setClaim("amr", new String[] {amr});
	    }
	    
	    
	    if (extraAttribs != null) {
	    	for (String key : extraAttribs.keySet()) {
	    		claims.setClaim(key, extraAttribs.get(key));
	    	}
	    }
	    
	    if (actor != null) {
	    	JSONObject actorToAdd = new JSONObject();
	    	for (Object key : existingClaims.keySet()) {
	    		if (! ignoredClaims.contains((String) key)) {
	    			actorToAdd.put(key, actor.get(key));
	    		}
	    	}
	    	
	    	Map actorFromSubject = (Map) claims.getClaimValue("actor");
	    	if (actorFromSubject != null) {
	    		actorFromSubject.put("act", actorToAdd);
	    	} else {
	    		claims.setClaim("act", actorToAdd);
	    	}
	    }
	    
	    
	    
	    if (this.claimsUpdater != null) {
	    	this.claimsUpdater.updateClaimsBeforeSigning(dn, cfg, url, trust, nonce, extraAttribs, entry, user, claims);
	    }
	    
	    
		return claims;
	}
	
	

	public void removeSession(OidcSessionState oidcSession) {
		try {
			
			this.sessionStore.deleteSession(oidcSession.getSessionID());
		} catch (Exception e) {
			logger.error("Could not delete session",e);
		}
		
	}

	public HashMap<String, OpenIDConnectTrust> getTrusts() {
		return trusts;
	}

	public OidcSessionState getSessionByRefreshToken(String refreshToken) throws Exception {
		return this.sessionStore.getSession(refreshToken);
	}
	
	public OidcSessionState getSessionByAccessToken(String accessToken) throws Exception {
		
		
		
		
		
		JsonWebSignature jws = new JsonWebSignature();
		jws.setCompactSerialization(accessToken);
		jws.setKey(GlobalEntries.getGlobalEntries().getConfigManager().getCertificate(this.jwtSigningKeyName).getPublicKey());
		
		if (! jws.verifySignature()) {
			throw new Exception("Invalid access_token signature");
		}
		
		JwtClaims claims = JwtClaims.parse(jws.getPayload());
		String encryptedSessionID = claims.getStringClaimValue("session_id");
		
		String sessionID = this.decryptToken(this.sessionKeyName, new Gson(), encryptedSessionID);
		return this.sessionStore.getSession(sessionID);
		
	}

	public void updateToken(OidcSessionState session) throws Exception {
		this.sessionStore.resetSession(session);
		
	}

	public String decryptClientSecret(String keyName,String encryptedClientSecret) throws Exception {
		return this.decryptToken(keyName, new Gson(), encryptedClientSecret);
	}

	

	public String getJwtSigningKeyName() {
		return this.jwtSigningKeyName;
	}

	public void clearExpiredSessions() {
		try {
			this.sessionStore.cleanOldSessions();
		} catch (Exception e) {
			logger.error("Could not clear sessions",e);
		}
		
	}
	
	public String getUidAttributeFromMap() {
		return this.subAttribute;
	}
	
	public MapIdentity getMapper() {
		return this.mapper;
	}

	public Map<String, String> getAuthChainToAmr() {
		return authChainToAmr;
	}

	public Map<String, String> getAmrToAuthChain() {
		return amrToAuthChain;
	}

	public void removeAllSessions(OidcSessionState session) throws Exception {
		this.sessionStore.deleteAllSessions(session.getSessionID());
		
	}
	
	
	
}


class TokenData {
	String subjectUid;
	String amr;
	JSONObject root;
	
}
