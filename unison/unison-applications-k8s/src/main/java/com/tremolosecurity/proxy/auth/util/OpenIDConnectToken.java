/*******************************************************************************
 * Copyright 2016, 2018 Tremolo Security, Inc.
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
import java.util.UUID;

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
import com.tremolosecurity.idp.providers.oidc.model.OidcSessionState;
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
	private OidcSessionState oidcSession;
	private ApplicationType app;
	
	public OidcSessionState getSessionState() {
		return this.oidcSession;
	}

	public void replaceState() throws Exception {
		
        HashMap<String,OpenIDConnectIdP> oidcIdPs = (HashMap<String,OpenIDConnectIdP>) GlobalEntries.getGlobalEntries().get(OpenIDConnectIdP.UNISON_OPENIDCONNECT_IDPS);
        
        OpenIDConnectIdP idp = oidcIdPs.get(this.idpName);
        this.oidcSession = idp.getSessionStore().getSession(this.oidcSession.getSessionID());
	}
	
	public OpenIDConnectToken(String idpName, String trustName, String urlOfRequest) {
		this.idpName = idpName;
		this.trustName = trustName;
		this.urlOfRequest = urlOfRequest;
	}

	public void generateToken(HttpServletRequest request) throws ServletException, JoseException,
			LDAPException, ProvisioningException, MalformedClaimException, UnsupportedEncodingException, IOException {

		AuthController ac = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL));
		

		HashMap<String, OpenIDConnectIdP> idps = (HashMap<String, OpenIDConnectIdP>) GlobalEntries.getGlobalEntries()
				.get(OpenIDConnectIdP.UNISON_OPENIDCONNECT_IDPS);

		OpenIDConnectIdP idp = idps.get(this.idpName);
		if (idp == null) {
			throw new ServletException("Could not find idp '" + this.idpName + "'");
		}

		generateClaimsData(ac, idp);
		
		
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		
		OpenIDConnectAccessToken accessToken = new OpenIDConnectAccessToken();
		oidcSession = idp.createUserSession(request, this.trustName, holder, idp.getTrusts().get(this.trustName), ac.getAuthInfo().getUserDN(), GlobalEntries.getGlobalEntries().getConfigManager(), accessToken,UUID.randomUUID().toString());
		
		
		
	}

	private void generateClaimsData(AuthController ac, OpenIDConnectIdP idp)
			throws JoseException, LDAPException, ProvisioningException, MalformedURLException, MalformedClaimException {
		this.idClaims = idp.generateClaims(ac.getAuthInfo(), GlobalEntries.getGlobalEntries().getConfigManager(),
				trustName, this.urlOfRequest);
		this.idJws = idp.generateJWS(getClaims());
		this.idEncodedJSON = this.idJws.getCompactSerialization();

		this.accessClaims = idp.generateClaims(ac.getAuthInfo(), GlobalEntries.getGlobalEntries().getConfigManager(),
				trustName, this.urlOfRequest);
		this.accessJws = idp.generateJWS(getClaims());
		this.accessEncodedJSON = this.idJws.getCompactSerialization();

		this.expires = new DateTime(idClaims.getExpirationTime().getValueInMillis());
	}
	
	public void refreshProxyToken(HttpServletRequest request) throws ServletException, MalformedURLException, MalformedClaimException, JoseException, LDAPException, ProvisioningException {
		AuthController ac = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL));
		

		HashMap<String, OpenIDConnectIdP> idps = (HashMap<String, OpenIDConnectIdP>) GlobalEntries.getGlobalEntries()
				.get(OpenIDConnectIdP.UNISON_OPENIDCONNECT_IDPS);

		OpenIDConnectIdP idp = idps.get(this.idpName);
		if (idp == null) {
			throw new ServletException("Could not find idp '" + this.idpName + "'");
		}

		generateClaimsData(ac, idp);
		
	}

	
	
	
	public JwtClaims getClaims() {
		return idClaims;
	}

	public JsonWebSignature getJws() {
		return idJws;
	}

	public String getEncodedIdJSON() {
		//System.out.println("in encoded json : '" + this.idEncodedJSON + "'");
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

	
	public String getRefreshToken() throws Exception {
		HashMap<String, OpenIDConnectIdP> idps = (HashMap<String, OpenIDConnectIdP>) GlobalEntries.getGlobalEntries()
				.get(OpenIDConnectIdP.UNISON_OPENIDCONNECT_IDPS);

		OpenIDConnectIdP idp = idps.get(this.idpName);
		return idp.getSessionStore().getSession(this.oidcSession.getSessionID()).getRefreshToken();
		
	}
	

	

}
