/*******************************************************************************
 * Copyright 2021 Tremolo Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package com.tremolosecurity.idp.providers.oidc.db;

public class StsRequest {
	boolean impersonation;
	boolean delegation;
	String audience;
	String subjectToken;
	String subjectTokenType;
	String actorToken;
	String actorTokenType;
	
	public StsRequest() {
		
	}
	
	
	public boolean isImpersonation() {
		return impersonation;
	}
	public void setImpersonation(boolean impersonation) {
		this.impersonation = impersonation;
	}
	public boolean isDelegation() {
		return delegation;
	}
	public void setDelegation(boolean delegation) {
		this.delegation = delegation;
	}
	public String getAudience() {
		return audience;
	}
	public void setAudience(String audience) {
		this.audience = audience;
	}
	public String getSubjectToken() {
		return subjectToken;
	}
	public void setSubjectToken(String subjectToken) {
		this.subjectToken = subjectToken;
	}
	public String getSubjectTokenType() {
		return subjectTokenType;
	}
	public void setSubjectTokenType(String subjectTokenType) {
		this.subjectTokenType = subjectTokenType;
	}


	public String getActorToken() {
		return actorToken;
	}


	public void setActorToken(String actorToken) {
		this.actorToken = actorToken;
	}


	public String getActorTokenType() {
		return actorTokenType;
	}


	public void setActorTokenType(String actorTokenType) {
		this.actorTokenType = actorTokenType;
	}
	
	
	
	
	
	
}
