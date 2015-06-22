/*
Copyright 2015 Tremolo Security, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/


package com.tremolosecurity.lastmile.undertow;

import io.undertow.security.api.AuthenticationMechanism;
import io.undertow.security.api.SecurityContext;
import io.undertow.server.HttpServerExchange;

public class UnisonAuthenticationMechanism implements AuthenticationMechanism {

	UnisonAccount account;
	
	public UnisonAuthenticationMechanism(UnisonAccount account) {
		this.account = account;
	}
	
	@Override
	public AuthenticationMechanismOutcome authenticate(
			HttpServerExchange exchange, SecurityContext securityContext) {
		System.err.println("in authenticate");
		securityContext.authenticationComplete(account, "FORM", false);
		return AuthenticationMechanismOutcome.AUTHENTICATED;
	}

	@Override
	public ChallengeResult sendChallenge(HttpServerExchange exchange,
			SecurityContext securityContext) {
		System.err.println("in send challenge");
		return new ChallengeResult(true,200);
	}

}
