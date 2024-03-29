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

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.tremolosecurity.proxy.az.AzRule;

public class OpenIDConnectTrust {
	HashSet<String> redirectURI;
	String clientID;
	String clientSecret;
	String trustName;
	String codeLastmileKeyName;
	
	String authChain;
	String idAttributeName;
	long codeTokenTimeToLive;
	long accessTokenTimeToLive;
	long accessTokenSkewMillis;

	boolean verifyRedirect;
	
	boolean signedUserInfo;
	
	
	boolean sts;
	
	List<AzRule> clientAzRules;
	List<AzRule> subjectAzRules;
	
	Set<String> allowedAudiences;
	
	boolean stsImpersonation;
	boolean stsDelegation;
	
	boolean enableClientCredentialGrant;

	public OpenIDConnectTrust() {
		this.redirectURI = new HashSet<String>();
		this.clientAzRules = new ArrayList<AzRule>();
		this.allowedAudiences = new HashSet<String>();
		this.subjectAzRules = new ArrayList<AzRule>();
	}
	
	public boolean isVerifyRedirect() {
		return this.verifyRedirect;
	}

	public void setVerifyRedirect(boolean verifyRedirect) {
		this.verifyRedirect = verifyRedirect;
	}

	public boolean isPublicEndpoint() {
		return publicEndpoint;
	}

	public void setPublicEndpoint(boolean publicEndpoint) {
		this.publicEndpoint = publicEndpoint;
	}

	boolean publicEndpoint;
	

	public String getClientID() {
		return clientID;
	}
	public void setClientID(String clientID) {
		this.clientID = clientID;
	}
	public String getClientSecret() {
		return clientSecret;
	}
	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}
	public String getTrustName() {
		return trustName;
	}
	public void setTrustName(String trustName) {
		this.trustName = trustName;
	}
	public String getCodeLastmileKeyName() {
		return codeLastmileKeyName;
	}
	public void setCodeLastmileKeyName(String codeLastmileKeyName) {
		this.codeLastmileKeyName = codeLastmileKeyName;
	}
	
	
	public String getAuthChain() {
		return authChain;
	}
	public void setAuthChain(String authChain) {
		this.authChain = authChain;
	}
	public String getIdAttributeName() {
		return idAttributeName;
	}
	public void setIdAttributeName(String idAttributeName) {
		this.idAttributeName = idAttributeName;
	}
	public long getCodeTokenTimeToLive() {
		return codeTokenTimeToLive;
	}
	public void setCodeTokenTimeToLive(long tokenTimeToLive) {
		this.codeTokenTimeToLive = tokenTimeToLive;
	}
	public long getAccessTokenTimeToLive() {
		return accessTokenTimeToLive;
	}
	public void setAccessTokenTimeToLive(long accessTokenTimeToLive) {
		this.accessTokenTimeToLive = accessTokenTimeToLive;
	}
	public long getAccessTokenSkewMillis() {
		return accessTokenSkewMillis;
	}
	public void setAccessTokenSkewMillis(long accessTokenSkewMillis) {
		this.accessTokenSkewMillis = accessTokenSkewMillis;
	}

	public boolean isSignedUserInfo() {
		return signedUserInfo;
	}

	public void setSignedUserInfo(boolean signedUserInfo) {
		this.signedUserInfo = signedUserInfo;
	}

	public HashSet<String> getRedirectURI() {
		return redirectURI;
	}

	public void setRedirectURI(HashSet<String> redirectURI) {
		this.redirectURI = redirectURI;
	}

	public boolean isSts() {
		return sts;
	}

	public void setSts(boolean sts) {
		this.sts = sts;
	}

	public List<AzRule> getClientAzRules() {
		return clientAzRules;
	}

	public Set<String> getAllowedAudiences() {
		return allowedAudiences;
	}

	public List<AzRule> getSubjectAzRules() {
		return subjectAzRules;
	}

	public boolean isStsImpersonation() {
		return stsImpersonation;
	}

	public void setStsImpersonation(boolean stsImpersonation) {
		this.stsImpersonation = stsImpersonation;
	}

	public boolean isStsDelegation() {
		return stsDelegation;
	}

	public void setStsDelegation(boolean stsDelegation) {
		this.stsDelegation = stsDelegation;
	}

	public boolean isEnableClientCredentialGrant() {
		return enableClientCredentialGrant;
	}

	public void setEnableClientCredentialGrant(boolean enableClientCredentialGrant) {
		this.enableClientCredentialGrant = enableClientCredentialGrant;
	}
	
	
	
	
	
	
	
}
