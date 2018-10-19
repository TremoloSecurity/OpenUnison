/*******************************************************************************
 * Copyright 2015, 2016 Tremolo Security, Inc.
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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
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

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.ApplicationType;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.idp.providers.oidc.db.DbOidcSessionStore;
import com.tremolosecurity.idp.providers.oidc.model.OIDCSession;
import com.tremolosecurity.idp.providers.oidc.model.OidcSessionState;
import com.tremolosecurity.idp.providers.oidc.model.OpenIDConnectConfig;
import com.tremolosecurity.idp.providers.oidc.session.ClearOidcSessionOnLogout;
import com.tremolosecurity.idp.providers.oidc.model.OidcSessionStore;
import com.tremolosecurity.idp.server.IDP;
import com.tremolosecurity.idp.server.IdentityProvider;
import com.tremolosecurity.json.Token;
import com.tremolosecurity.log.AccessLog;
import com.tremolosecurity.log.AccessLog.AccessEvent;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.mapping.MapIdentity;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.auth.AzSys;
import com.tremolosecurity.proxy.auth.RequestHolder;
import com.tremolosecurity.proxy.auth.passwordreset.PasswordResetRequest;
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
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.server.StopableThread;

public class OpenIDConnectIdP implements IdentityProvider {

	public static final String UNISON_OPENIDCONNECT_IDPS = "unison.openidconnectidps";

	static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(OpenIDConnectIdP.class.getName());
	
	private static final String TRANSACTION_DATA = "unison.openidconnect.session";

	public static final String UNISON_SESSION_OIDC_ACCESS_TOKEN = "unison.session.oidc.access.token";
	public static final String UNISON_SESSION_OIDC_ID_TOKEN = "unison.session.oidc.id.token";
	String idpName;
	HashMap<String,OpenIDConnectTrust> trusts;
	String jwtSigningKeyName;

	OidcSessionStore sessionStore;
	
	
	private MapIdentity mapper;
	
	
	private String sessionKeyName;
	
	public void doDelete(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {


	}

	public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
		String action = (String) request.getAttribute(IDP.ACTION_NAME);
		
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		if (holder == null) {
			throw new ServletException("Holder is null");
		}
		
		AuthController ac = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL));
		
		
		if (action.equalsIgnoreCase(".well-known/openid-configuration")) {
			
			Gson gson = new GsonBuilder().setPrettyPrinting().create();
			String json = gson.toJson(new OpenIDConnectConfig(this.idpName,request,mapper));
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
			
			OpenIDConnectTransaction transaction = new OpenIDConnectTransaction();
			transaction.setClientID(clientID);
			transaction.setResponseCode(responseCode);
			transaction.setNonce(nonce);
			
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

				if (! trust.getRedirectURI().equals(redirectURI)) {
					StringBuffer b = new StringBuffer();
					b.append(trust.getRedirectURI()).append("?error=unauthorized_client");
					logger.warn("Invalid redirect");
					
					
					AccessLog.log(AccessEvent.AzFail, holder.getApp(), (HttpServletRequest) request, ac.getAuthInfo() , "NONE");
					
					response.sendRedirect(b.toString());
					return;
				}

				transaction.setRedirectURI(trust.getRedirectURI());

			} else {
				transaction.setRedirectURI(redirectURI);
			}
			
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
		
		
		StringBuffer b = genFinalURL(req);
		
		
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

	public void doHead(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {


	}

	public void doOptions(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {


	}

	public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
		
		
		
		
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

			
			logger.info("Client ID : '" + clientID + "'");
			
			if (clientID == null) {
				logger.info("no client id parameter");
				//this means that the clientid is in the Authorization header
				String azHeader = request.getHeader("Authorization");
				logger.info("authorization header :'" + azHeader + "'");
				azHeader = azHeader.substring(azHeader.indexOf(' ') + 1).trim();
				azHeader = new String(org.apache.commons.codec.binary.Base64.decodeBase64(azHeader));
				clientID = azHeader.substring(0,azHeader.indexOf(':'));
				clientSecret = azHeader.substring(azHeader.indexOf(':') + 1);
			}


			logger.info("Final Client ID : '" + clientID + "'");
			
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
				
				
			} else {
				completeUserLogin(request, response, code, clientID, clientSecret, holder, ac.getAuthInfo());
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
		
		claims.setGeneratedJwtId(); // a unique identifier for the token
		claims.setIssuedAtToNow();  // when the token was issued/created (now)
		claims.setNotBeforeMinutesInThePast(trusts.get(dbSession.getClientID()).getAccessTokenSkewMillis() / 1000 / 60); // time before which the token is not yet valid (2 minutes ago)
		claims.setExpirationTimeMinutesInTheFuture(trusts.get(dbSession.getClientID()).getAccessTokenTimeToLive() / 1000 / 60); // time when the token will expire (10 minutes from now)
		
		jws = new JsonWebSignature();
		jws.setPayload(claims.toJson());
		jws.setKey(GlobalEntries.getGlobalEntries().getConfigManager().getPrivateKey(this.jwtSigningKeyName));
		jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
		
		response.setContentType("application/jwt");
		response.getOutputStream().write(jws.getCompactSerialization().getBytes("UTF-8"));
		
		AuthInfo remUser = new AuthInfo();
		remUser.setUserDN(dbSession.getUserDN());
		
		AccessLog.log(AccessEvent.AzSuccess, holder.getApp(), (HttpServletRequest) request, remUser ,  "NONE");
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
		logger.info("Decrypted session id : '" + decryptedRefreshToken + "'");
		OidcSessionState session = this.getSessionByRefreshToken(decryptedRefreshToken);

		if (session == null) {
			logger.warn("Session does not exist from refresh_token");
			AccessLog.log(AccessEvent.AzFail, holder.getApp(), (HttpServletRequest) request, authData ,  "NONE");
			response.sendError(401);
			return;
		}
		
		if (! session.getRefreshToken().equals(refreshToken)) {
			logger.warn("Session does not exist from refresh_token");
			AccessLog.log(AccessEvent.AzFail, holder.getApp(), (HttpServletRequest) request, authData ,  "NONE");
			response.sendError(401);
			return;
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
			String clientID, String clientSecret, UrlHolder holder, AuthInfo authData)
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
		
		for (Attribute attr : lmreq.getAttributes()) {
			if (attr.getName().equalsIgnoreCase("dn")) {
				dn = attr;
			} else if (attr.getName().equalsIgnoreCase("scope")) {
				scopes = attr;
			} else if (attr.getName().equalsIgnoreCase("nonce")) {
				nonce = attr;
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
		
		OidcSessionState oidcSession = createUserSession(request, clientID, holder, trust, dn.getValues().get(0), cfgMgr, access,(nonce != null ? nonce.getValues().get(0) : UUID.randomUUID().toString())); 
		
		
		
		
		
		
		
		access.setRefresh_token(oidcSession.getRefreshToken());
		
		
		Gson gson = new Gson();
		String json = gson.toJson(access);
		
		response.setContentType("text/json");
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
			OpenIDConnectTrust trust, String dn,  ConfigManager cfgMgr, OpenIDConnectAccessToken access,String nonce)
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
			accessToken = this.produceJWT(this.generateClaims(dn,  cfgMgr, new URL(request.getRequestURL().toString()), trust,nonce,extraAttribs),cfgMgr).getCompactSerialization();
		} catch (JoseException | LDAPException | ProvisioningException e1) {
			throw new ServletException("Could not generate jwt",e1);
		} 
		
		
		
		
		
		
		
		
		access.setAccess_token(accessToken);
		access.setExpires_in((int) (trust.getAccessTokenTimeToLive() / 1000));
		try {
			access.setId_token(this.produceJWT(this.generateClaims(dn,  cfgMgr, new URL(request.getRequestURL().toString()), trust,nonce,null),cfgMgr).getCompactSerialization());
		} catch (Exception e) {
			throw new ServletException("Could not generate JWT",e);
		} 
		
		access.setToken_type("Bearer");
		OidcSessionState oidcSession = null;
		
		try {			
			oidcSession = this.storeSession(access, holder.getApp(), trust.getCodeLastmileKeyName(), clientID,dn,sessionID);
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
		
		request.setAttribute(AzSys.FORCE, "true");
		NextSys completeFed = new NextSys() {

			
			public void nextSys(final HttpServletRequest request,
					final HttpServletResponse response) throws IOException,
					ServletException {
				//System.out.println("Authorized!!!!");
				
				
				final AuthInfo authInfo = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
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
		this.trusts = new HashMap<String,OpenIDConnectTrust>();
		for (String trustName : trustCfg.keySet()) {
			HashMap<String,Attribute> attrs = trustCfg.get(trustName);
			OpenIDConnectTrust trust = new OpenIDConnectTrust();
			trust.setClientID(attrs.get("clientID").getValues().get(0));
			trust.setClientSecret(attrs.get("clientSecret").getValues().get(0));
			trust.setRedirectURI(attrs.get("redirectURI").getValues().get(0));
			trust.setCodeLastmileKeyName(attrs.get("codeLastMileKeyName").getValues().get(0));
			trust.setAuthChain(attrs.get("authChainName").getValues().get(0));
			trust.setCodeTokenTimeToLive(Long.parseLong(attrs.get("codeTokenSkewMilis").getValues().get(0)));
			trust.setAccessTokenTimeToLive(Long.parseLong(attrs.get("accessTokenTimeToLive").getValues().get(0)));
			trust.setAccessTokenSkewMillis(Long.parseLong(attrs.get("accessTokenSkewMillis").getValues().get(0)));

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
		
		this.mapper = mapper;
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
		
		
        DbOidcSessionStore dbSessionStore = new DbOidcSessionStore();
        this.sessionStore = dbSessionStore;
        try {
			this.sessionStore.init(localIdPName, ctx, init, trustCfg, mapper);
		} catch (Exception e) {
			logger.error("Could not initialize session store",e);
		}
        
        this.sessionKeyName = GlobalEntries.getGlobalEntries().getConfigManager().getApp(this.idpName).getCookieConfig().getKeyAlias();

	}

	public OidcSessionStore getSessionStore() {
		return this.sessionStore;
	}

	public JsonWebSignature generateJWS(JwtClaims claims) throws JoseException, LDAPException, ProvisioningException, MalformedURLException {
		
		
		return this.produceJWT(claims,GlobalEntries.getGlobalEntries().getConfigManager());
	}
	
	
	public JwtClaims generateClaims(AuthInfo user,ConfigManager cfg,String trustName,String urlOfRequest) throws JoseException, LDAPException, ProvisioningException, MalformedURLException {
		String url = urlOfRequest;
		int end = url.indexOf('/',url.indexOf("://") + 3);
		if (end != -1) {
			url = url.substring(0,end);
		}
		
		return generateClaims(user.getUserDN(), cfg, new URL(url), this.trusts.get(trustName), null,null);
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

	private JwtClaims generateClaims(String dn, ConfigManager cfg, URL url, OpenIDConnectTrust trust, String nonce, HashMap<String, String> extraAttribs)
			throws LDAPException, ProvisioningException {
		StringBuffer issuer = new StringBuffer();
		issuer.append(url.getProtocol()).append("://").append(url.getHost());
		if (url.getPort() > 0) {
			issuer.append(':').append(url.getPort());
		}
	
		issuer.append(cfg.getAuthIdPPath()).append(this.idpName);
		
		
		// Create the Claims, which will be the content of the JWT
	    JwtClaims claims = new JwtClaims();
	    claims.setIssuer(issuer.toString());  // who creates the token and signs it
	    claims.setAudience(trust.getClientID()); // to whom the token is intended to be sent
	    claims.setExpirationTimeMinutesInTheFuture(trust.getAccessTokenTimeToLive() / 1000 / 60); // time when the token will expire (10 minutes from now)
	    
	    claims.setGeneratedJwtId(); // a unique identifier for the token
	    claims.setIssuedAtToNow();  // when the token was issued/created (now)
	    claims.setNotBeforeMinutesInThePast(trust.getAccessTokenSkewMillis() / 1000 / 60); // time before which the token is not yet valid (2 minutes ago)
	    //claims.setSubject(dn); // the subject/principal is whom the token is about
	    if (nonce != null) {
	    	claims.setClaim("nonce", nonce);
	    }
	    ArrayList<String> attrs = new ArrayList<String>();
	    LDAPSearchResults res = cfg.getMyVD().search(dn,0, "(objectClass=*)", attrs);
	    
	    res.hasMore();
	    LDAPEntry entry = res.next();
	    
	    User user = new User(entry); 
	    user = this.mapper.mapUser(user, true);
	    
	    
	    
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
	    
	    
	    
	    if (extraAttribs != null) {
	    	for (String key : extraAttribs.keySet()) {
	    		claims.setClaim(key, extraAttribs.get(key));
	    	}
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
	
	
}
