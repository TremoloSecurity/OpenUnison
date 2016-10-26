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

import java.sql.Timestamp;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "oidcSession")
public class OIDCSession {
		
	private int id;
	
	private String accessToken;
	private String idToken;
	private String refreshToken;
	
	private Timestamp sessionExpires;
	private String applicationName;
	private String encryptedRefreshToken;
	private String encryptedClientSecret;
	
	@Id
	@GeneratedValue(strategy=GenerationType.IDENTITY)
	@Column(name = "id", unique = true, nullable = false)
	public int getId() {
		return id;
	}
	public void setId(int id) {
		this.id = id;
	}
	
	
	@Column(name = "accessToken",columnDefinition = "TEXT")
	public String getAccessToken() {
		return accessToken;
	}
	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}
	
	@Column(name = "idToken",columnDefinition = "TEXT")
	public String getIdToken() {
		return idToken;
	}
	public void setIdToken(String idToken) {
		this.idToken = idToken;
	}
	
	@Column(name = "refreshToken",unique=true)
	public String getRefreshToken() {
		return refreshToken;
	}
	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}
	
	
	
	@Column(name = "sessionExpires")
	public Timestamp getSessionExpires() {
		return sessionExpires;
	}
	public void setSessionExpires(Timestamp sessionExpires) {
		this.sessionExpires = sessionExpires;
	}
	
	@Column(name = "applicationName")
	public String getApplicationName() {
		return applicationName;
	}
	public void setApplicationName(String applicationName) {
		this.applicationName = applicationName;
	}
	
	@Column(name = "encryptedRefreshToken",columnDefinition = "TEXT")
	public String getEncryptedRefreshToken() {
		return encryptedRefreshToken;
	}
	public void setEncryptedRefreshToken(String encryptedRefreshToken) {
		this.encryptedRefreshToken = encryptedRefreshToken;
	}
	
	
	@Column(name = "encryptedClientSecret",columnDefinition = "TEXT")
	public String getEncryptedClientSecret() {
		return encryptedClientSecret;
	}
	public void setEncryptedClientSecret(String encryptedClientSecret) {
		this.encryptedClientSecret = encryptedClientSecret;
	}
	
	
	
	
	
	
}
