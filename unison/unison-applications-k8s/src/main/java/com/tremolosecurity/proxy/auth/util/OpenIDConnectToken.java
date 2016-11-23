/*******************************************************************************
 * Copyright 2016 Tremolo Security, Inc.
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
package com.tremolosecurity.proxy.auth.util;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.joda.time.DateTime;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.lang.JoseException;

import com.novell.ldap.LDAPException;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.ApplicationType;
import com.tremolosecurity.idp.providers.OpenIDConnectAccessToken;
import com.tremolosecurity.idp.providers.OpenIDConnectIdP;
import com.tremolosecurity.idp.providers.oidc.model.OIDCSession;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.RequestHolder;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;

public class OpenIDConnectToken {
	JwtClaims idClaims;
	JsonWebSignature idJws;
	String idEncodedJSON;

	JwtClaims accessClaims;
	JsonWebSignature accessJws;
	String accessEncodedJSON;

	DateTime expires;
	String trustName;
	String idpName;
	String urlOfRequest;
	private OIDCSession oidcSession;
	private ApplicationType app;

	public OpenIDConnectToken(String idpName, String trustName, String urlOfRequest) {
		this.idpName = idpName;
		this.trustName = trustName;
		this.urlOfRequest = urlOfRequest;
	}

	public void generateToken(HttpSession session) throws ServletException, MalformedURLException, JoseException,
			LDAPException, ProvisioningException, MalformedClaimException {

		AuthController ac = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL));

		HashMap<String, OpenIDConnectIdP> idps = (HashMap<String, OpenIDConnectIdP>) GlobalEntries.getGlobalEntries()
				.get(OpenIDConnectIdP.UNISON_OPENIDCONNECT_IDPS);

		OpenIDConnectIdP idp = idps.get(this.idpName);
		if (idp == null) {
			throw new ServletException("Could not find idp '" + this.idpName + "'");
		}

		this.idClaims = idp.generateClaims(ac.getAuthInfo(), GlobalEntries.getGlobalEntries().getConfigManager(),
				trustName, this.urlOfRequest);
		this.idJws = idp.generateJWS(getClaims());
		this.idEncodedJSON = this.idJws.getCompactSerialization();

		this.accessClaims = idp.generateClaims(ac.getAuthInfo(), GlobalEntries.getGlobalEntries().getConfigManager(),
				trustName, this.urlOfRequest);
		this.accessJws = idp.generateJWS(getClaims());
		this.accessEncodedJSON = this.idJws.getCompactSerialization();

		this.expires = new DateTime(idClaims.getExpirationTime().getValueInMillis());
		
		if (this.oidcSession != null) {
			this.oidcSession.setAccessToken(this.accessEncodedJSON);
			this.oidcSession.setIdToken(this.idEncodedJSON);
			idp.updateToken(oidcSession);
		}
		
	}

	
	public void loadFromDB(HttpSession session) throws Exception {
		AuthController ac = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL));

		HashMap<String, OpenIDConnectIdP> idps = (HashMap<String, OpenIDConnectIdP>) GlobalEntries.getGlobalEntries()
				.get(OpenIDConnectIdP.UNISON_OPENIDCONNECT_IDPS);

		OpenIDConnectIdP idp = idps.get(this.idpName);
		
		
		OIDCSession localSession = idp.reloadSession(this.oidcSession);
		
		this.oidcSession = localSession;
		
		JsonWebSignature jws = new JsonWebSignature();
		jws.setCompactSerialization(oidcSession.getIdToken());
		jws.setKey(GlobalEntries.getGlobalEntries().getConfigManager().getCertificate(idp.getJwtSigningKeyName()).getPublicKey());
		
		if (! jws.verifySignature()) {
			throw new Exception("Could not verify id_token");
		}
		this.idJws = jws;
		this.idClaims = JwtClaims.parse(jws.getPayload());
		this.idEncodedJSON = oidcSession.getIdToken();
		this.expires = new DateTime(idClaims.getExpirationTime().getValueInMillis());
		
		jws = new JsonWebSignature();
		jws.setCompactSerialization(oidcSession.getAccessToken());
		jws.setKey(GlobalEntries.getGlobalEntries().getConfigManager().getCertificate(idp.getJwtSigningKeyName()).getPublicKey());
		
		if (! jws.verifySignature()) {
			throw new Exception("Could not verify access_token");
		}
		this.accessJws = jws;
		this.accessClaims = JwtClaims.parse(jws.getPayload());
		this.accessEncodedJSON = oidcSession.getAccessToken();
		
		
	}
	
	public JwtClaims getClaims() {
		return idClaims;
	}

	public JsonWebSignature getJws() {
		return idJws;
	}

	public String getEncodedIdJSON() {
		return idEncodedJSON;
	}

	public DateTime getExpires() {
		return expires;
	}

	public String getTrustName() {
		return trustName;
	}

	public boolean isExpired() {
		return this.expires.isBeforeNow();
	}

	public String getIdpName() {
		return idpName;
	}

	public void createToken(HttpServletRequest request) throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, MalformedClaimException,
			ServletException, JoseException, LDAPException, ProvisioningException, IOException {
		this.generateToken(request.getSession());
		
		AuthController ac = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL));
		
		OpenIDConnectAccessToken access = new OpenIDConnectAccessToken();

		access.setAccess_token(this.accessEncodedJSON);
		access.setId_token(this.idEncodedJSON);

		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		this.app = holder.getApp();

		HashMap<String, OpenIDConnectIdP> idps = (HashMap<String, OpenIDConnectIdP>) GlobalEntries.getGlobalEntries()
				.get(OpenIDConnectIdP.UNISON_OPENIDCONNECT_IDPS);

		this.oidcSession = idps.get(this.idpName).storeSession(access, holder.getApp(),
				idps.get(idpName).getTrusts().get(this.trustName).getCodeLastmileKeyName(), request, ac.getAuthInfo().getUserDN(), this.trustName);

	}

	public String getAccessEncodedJSON() {
		return accessEncodedJSON;
	}

	public String getRefreshToken() {
		return this.oidcSession.getEncryptedRefreshToken();
	}
	
	public String getDecryptedClientSecret() throws Exception {
		HashMap<String, OpenIDConnectIdP> idps = (HashMap<String, OpenIDConnectIdP>) GlobalEntries.getGlobalEntries()
				.get(OpenIDConnectIdP.UNISON_OPENIDCONNECT_IDPS);
		OpenIDConnectIdP idp = idps.get(this.idpName);
		return idp.decryptClientSecret(idp.getTrusts().get(this.trustName).getCodeLastmileKeyName(),this.oidcSession.getEncryptedClientSecret());
		
	}
}
