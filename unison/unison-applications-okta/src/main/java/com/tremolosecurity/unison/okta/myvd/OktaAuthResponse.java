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
package com.tremolosecurity.unison.okta.myvd;

import org.apache.log4j.Logger;

import com.novell.ldap.LDAPException;
import com.okta.authn.sdk.AuthenticationStateHandler;
import com.okta.authn.sdk.resource.AuthenticationResponse;

public class OktaAuthResponse implements AuthenticationStateHandler {
	
	static Logger logger = Logger.getLogger(OktaAuthResponse.class);
	
	LDAPException result;
	String userid;
	
	public OktaAuthResponse(String userid) {
		this.userid = userid;
	}

	@Override
	public void handleUnauthenticated(AuthenticationResponse unauthenticatedResponse) {
		StringBuilder sb = new StringBuilder();
		sb.append(this.userid).append(" unauthenticated");
		logger.warn(sb.toString());
		this.result = new LDAPException("Could not authenticate",LDAPException.INVALID_CREDENTIALS,LDAPException.resultCodeToString(LDAPException.INVALID_CREDENTIALS));

	}

	@Override
	public void handlePasswordWarning(AuthenticationResponse passwordWarning) {
		StringBuilder sb = new StringBuilder();
		sb.append(this.userid).append(" password warning");
		logger.warn(sb.toString());
		if (passwordWarning.getSessionToken() == null) {
			this.result = new LDAPException("Could not authenticate",LDAPException.INVALID_CREDENTIALS,LDAPException.resultCodeToString(LDAPException.INVALID_CREDENTIALS));
		}
		

	}

	@Override
	public void handlePasswordExpired(AuthenticationResponse passwordExpired) {
		StringBuilder sb = new StringBuilder();
		sb.append(this.userid).append(" password expired");
		logger.warn(sb.toString());
		
		this.result = new LDAPException("Could not authenticate",LDAPException.INVALID_CREDENTIALS,LDAPException.resultCodeToString(LDAPException.INVALID_CREDENTIALS));
		

	}

	@Override
	public void handleRecovery(AuthenticationResponse recovery) {
		StringBuilder sb = new StringBuilder();
		sb.append(this.userid).append(" recovery");
		logger.warn(sb.toString());
		this.result = new LDAPException("Could not authenticate",LDAPException.INVALID_CREDENTIALS,LDAPException.resultCodeToString(LDAPException.INVALID_CREDENTIALS));
		
	}

	@Override
	public void handleRecoveryChallenge(AuthenticationResponse recoveryChallenge) {
		StringBuilder sb = new StringBuilder();
		sb.append(this.userid).append(" recovery challenge");
		logger.warn(sb.toString());
		
		this.result = new LDAPException("Could not authenticate",LDAPException.INVALID_CREDENTIALS,LDAPException.resultCodeToString(LDAPException.INVALID_CREDENTIALS));
		

	}

	@Override
	public void handlePasswordReset(AuthenticationResponse passwordReset) {
		StringBuilder sb = new StringBuilder();
		sb.append(this.userid).append(" password reset");
		logger.warn(sb.toString());
		
		this.result = new LDAPException("Could not authenticate",LDAPException.INVALID_CREDENTIALS,LDAPException.resultCodeToString(LDAPException.INVALID_CREDENTIALS));
		

	}

	@Override
	public void handleLockedOut(AuthenticationResponse lockedOut) {
		StringBuilder sb = new StringBuilder();
		sb.append(this.userid).append(" locked out");
		logger.warn(sb.toString());
		
		this.result = new LDAPException("Could not authenticate",LDAPException.INVALID_CREDENTIALS,LDAPException.resultCodeToString(LDAPException.INVALID_CREDENTIALS));
		

	}

	@Override
	public void handleMfaRequired(AuthenticationResponse mfaRequiredResponse) {
		StringBuilder sb = new StringBuilder();
		sb.append(this.userid).append(" mfa required");
		logger.warn(sb.toString());
		
		this.result = new LDAPException("Could not authenticate",LDAPException.INVALID_CREDENTIALS,LDAPException.resultCodeToString(LDAPException.INVALID_CREDENTIALS));
		

	}

	@Override
	public void handleMfaEnroll(AuthenticationResponse mfaEnroll) {
		StringBuilder sb = new StringBuilder();
		sb.append(this.userid).append(" mfa enroll");
		logger.warn(sb.toString());
		
		this.result = new LDAPException("Could not authenticate",LDAPException.INVALID_CREDENTIALS,LDAPException.resultCodeToString(LDAPException.INVALID_CREDENTIALS));
		

	}

	@Override
	public void handleMfaEnrollActivate(AuthenticationResponse mfaEnrollActivate) {
		StringBuilder sb = new StringBuilder();
		sb.append(this.userid).append(" mfa enroll activate");
		logger.warn(sb.toString());
		
		this.result = new LDAPException("Could not authenticate",LDAPException.INVALID_CREDENTIALS,LDAPException.resultCodeToString(LDAPException.INVALID_CREDENTIALS));
		

	}

	@Override
	public void handleMfaChallenge(AuthenticationResponse mfaChallengeResponse) {
		StringBuilder sb = new StringBuilder();
		sb.append(this.userid).append(" mfa challenge");
		logger.warn(sb.toString());
		
		this.result = new LDAPException("Could not authenticate",LDAPException.INVALID_CREDENTIALS,LDAPException.resultCodeToString(LDAPException.INVALID_CREDENTIALS));
		

	}

	@Override
	public void handleSuccess(AuthenticationResponse successResponse) {

		if (successResponse.getSessionToken() == null) {
			this.result = new LDAPException("Could not authenticate",LDAPException.INVALID_CREDENTIALS,LDAPException.resultCodeToString(LDAPException.INVALID_CREDENTIALS));
		}
		

	}

	@Override
	public void handleUnknown(AuthenticationResponse unknownResponse) {
		StringBuilder sb = new StringBuilder();
		sb.append(this.userid).append(" unknown");
		logger.warn(sb.toString());
		
		this.result = new LDAPException("Could not authenticate",LDAPException.INVALID_CREDENTIALS,LDAPException.resultCodeToString(LDAPException.INVALID_CREDENTIALS));
		

	}

	public LDAPException getResult() {
		return result;
	}
	
	

}
