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
package com.tremolosecurity.idp.providers.oidc.model;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.mapping.MapIdentity;
import com.tremolosecurity.proxy.util.ProxyConstants;

public class OpenIDConnectConfig {
	private String issuer;
	private String authorization_endpoint;
	private String token_endpoint;
	private String userinfo_endpoint;
	private String revocation_endpoint;
	private String jwks_uri;
	private List<String> response_types_supported;
	private List<String> subject_types_supported;
	private List<String> id_token_signing_alg_values_supported;
	private List<String> scopes_supported;
	private List<String> token_endpoint_auth_methods_supported;
	private List<String> claims_supported;
	private List<String> code_challenge_methods_supported;
	private transient String idpName;
	
	public OpenIDConnectConfig(String idpName,HttpServletRequest request, MapIdentity mapper) throws MalformedURLException {
		this.idpName = idpName;
		StringBuffer b = new StringBuffer();
		URL url = new URL(request.getRequestURL().toString());
		
		if (request.isSecure()) {
			b.append("https://");
		} else {
			b.append("http://");
		}
		
		b.append(url.getHost());
		
		if (url.getPort() != -1) {
			b.append(':').append(url.getPort());
		}
		
		
		ConfigManager cfg = (ConfigManager) request.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);
		//issuer.append(holder.getUrl().getUri());
		b.append(cfg.getAuthIdPPath()).append(this.idpName);
		
		this.issuer = b.toString();
		
		b.setLength(0);
		b.append(this.issuer).append("/auth");
		
		this.authorization_endpoint = b.toString();
		
		
		b.setLength(0);
		b.append(this.issuer).append("/token");
		this.token_endpoint = b.toString();
		
		
		b.setLength(0);
		b.append(this.issuer).append("/userinfo");
		this.userinfo_endpoint = b.toString();
		
		
		b.setLength(0);
		b.append(this.issuer).append("/revoke");
		this.revocation_endpoint = b.toString();
		
		
		b.setLength(0);
		b.append(this.issuer).append("/certs");
		this.jwks_uri = b.toString();
		
		this.response_types_supported = new ArrayList<String>();
		this.response_types_supported.add("code");
		this.response_types_supported.add("token");
		this.response_types_supported.add("id_token");
		this.response_types_supported.add("code token");
		this.response_types_supported.add("code id_token");
		this.response_types_supported.add("token id_token");
		this.response_types_supported.add("code token id_token");
		this.response_types_supported.add("none");
		
		this.subject_types_supported = new ArrayList<String>();
		this.subject_types_supported.add("public");
		
		this.id_token_signing_alg_values_supported = new ArrayList<String>();
		this.id_token_signing_alg_values_supported.add("RS256");
		
		this.scopes_supported = new ArrayList<String>();
		this.scopes_supported.add("openid");
		this.scopes_supported.add("email");
		this.scopes_supported.add("profile");
		
		this.token_endpoint_auth_methods_supported = new ArrayList<String>();
		this.token_endpoint_auth_methods_supported.add("client_secret_post");
		
		this.claims_supported = new ArrayList<String>();
		this.claims_supported.add("sub");
		this.claims_supported.add("aud");
		this.claims_supported.add("iss");
		this.claims_supported.add("exp");
		
		
		for (String claim : mapper.getAttributes()) {
			this.claims_supported.add(claim);
		}
		
		this.code_challenge_methods_supported = new ArrayList<String>();
		this.code_challenge_methods_supported.add("plain");
		this.code_challenge_methods_supported.add("S256");
		
		
	}

	public String getIssuer() {
		return issuer;
	}

	public String getAuthorization_endpoint() {
		return authorization_endpoint;
	}

	public String getToken_endpoint() {
		return token_endpoint;
	}

	public String getUserinfo_endpoint() {
		return userinfo_endpoint;
	}

	public String getRevocation_endpoint() {
		return revocation_endpoint;
	}

	public String getJwks_uri() {
		return jwks_uri;
	}

	public List<String> getResponse_types_supported() {
		return response_types_supported;
	}

	public List<String> getSubject_types_supported() {
		return subject_types_supported;
	}

	public List<String> getId_token_signing_alg_values_supported() {
		return id_token_signing_alg_values_supported;
	}

	public List<String> getScopes_supported() {
		return scopes_supported;
	}

	public List<String> getToken_endpoint_auth_methods_supported() {
		return token_endpoint_auth_methods_supported;
	}

	public List<String> getClaims_supported() {
		return claims_supported;
	}

	public List<String> getCode_challenge_methods_supported() {
		return code_challenge_methods_supported;
	}

	public String getIdpName() {
		return idpName;
	}
	
	
}
