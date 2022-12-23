/*******************************************************************************
 * Copyright 2018 Tremolo Security, Inc.
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

import java.util.ArrayList;
import java.util.List;

import org.joda.time.DateTime;

public class OidcSessionState {
	String sessionID;
	String encryptedIdToken;
	String encryptedAccessToken;
	DateTime expires;
	String clientID;
	String userDN;
	String refreshToken;
	
	List<ExpiredRefreshToken> expiredTokens;
	
	public OidcSessionState() {
		this.expiredTokens = new ArrayList<ExpiredRefreshToken>();
	}
	
	public String getSessionID() {
		return sessionID;
	}
	public void setSessionID(String sessionID) {
		this.sessionID = sessionID;
	}
	public String getEncryptedIdToken() {
		return encryptedIdToken;
	}
	public void setEncryptedIdToken(String encryptedIdToken) {
		this.encryptedIdToken = encryptedIdToken;
	}
	public DateTime getExpires() {
		return expires;
	}
	public void setExpires(DateTime expires) {
		this.expires = expires;
	}
	public String getClientID() {
		return clientID;
	}
	public void setClientID(String clientID) {
		this.clientID = clientID;
	}

	public String getEncryptedAccessToken() {
		return encryptedAccessToken;
	}
	public void setEncryptedAccessToken(String encryptedAccessToken) {
		this.encryptedAccessToken = encryptedAccessToken;
	}
	public String getUserDN() {
		return userDN;
	}
	public void setUserDN(String userDN) {
		this.userDN = userDN;
	}
	public String getRefreshToken() {
		return refreshToken;
	}
	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}

	public List<ExpiredRefreshToken> getExpiredTokens() {
		return expiredTokens;
	}
	
	
	
	
	
	
	
	
}
