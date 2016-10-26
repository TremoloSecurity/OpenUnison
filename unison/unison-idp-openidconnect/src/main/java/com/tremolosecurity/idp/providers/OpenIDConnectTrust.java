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

public class OpenIDConnectTrust {
	String redirectURI;
	String clientID;
	String clientSecret;
	String trustName;
	String codeLastmileKeyName;
	
	String authChain;
	String idAttributeName;
	long codeTokenTimeToLive;
	long accessTokenTimeToLive;
	long accessTokenSkewMillis;
	
	public String getRedirectURI() {
		return redirectURI;
	}
	public void setRedirectURI(String redirectURI) {
		this.redirectURI = redirectURI;
	}
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
	
	
	
	
}
