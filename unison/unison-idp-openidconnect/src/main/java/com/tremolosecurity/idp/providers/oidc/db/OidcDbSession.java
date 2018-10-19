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
package com.tremolosecurity.idp.providers.oidc.db;

import java.sql.Timestamp;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

import org.joda.time.DateTime;




@Entity
@Table(name = "oidcSessionState")
public class OidcDbSession  {

	
	
	String sessionID;
	String encryptedIdToken;
	Timestamp expires;
	String clientID;
	String encryptedAccessToken;
	String userDN;
	String refreshToken;
	
	@Id
	@Column(name = "sessionID",unique=true)
	public String getSessionID() {
		return sessionID;
	}
	public void setSessionID(String sessionID) {
		this.sessionID = sessionID;
	}
	
	@Column(name="encryptedIdToken",columnDefinition = "TEXT")
	public String getEncryptedIdToken() {
		return encryptedIdToken;
	}
	public void setEncryptedIdToken(String encryptedIdToken) {
		this.encryptedIdToken = encryptedIdToken;
	}
	
	@Column(name="expires")
	public Timestamp getExpires() {
		return expires;
	}
	public void setExpires(Timestamp expires) {
		this.expires = expires;
	}
	
	@Column(name="clientID")
	public String getClientID() {
		return clientID;
	}
	public void setClientID(String clientID) {
		this.clientID = clientID;
	}
	
	@Column(name="encryptedAccessToken",columnDefinition = "TEXT")
	public String getEncryptedAccessToken() {
		return encryptedAccessToken;
	}
	public void setEncryptedAccessToken(String encryptedAccessToken) {
		this.encryptedAccessToken = encryptedAccessToken;
	}
	
	@Column(name="userDN",columnDefinition="TEXT")
	public String getUserDN() {
		return userDN;
	}
	public void setUserDN(String userDN) {
		this.userDN = userDN;
	}
	
	@Column(name="refreshToken",columnDefinition="TEXT")
	public String getRefreshToken() {
		return refreshToken;
	}
	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}
	
	
	
	
	
	
	
	

}
