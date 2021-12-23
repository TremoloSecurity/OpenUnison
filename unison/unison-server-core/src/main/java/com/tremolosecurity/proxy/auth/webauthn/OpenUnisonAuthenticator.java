/*******************************************************************************
 * Copyright (c) 2021 Tremolo Security, Inc.
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
package com.tremolosecurity.proxy.auth.webauthn;

import java.util.Collections;
import java.util.Set;

import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;
import org.joda.time.DateTime;

import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;

public class OpenUnisonAuthenticator extends AuthenticatorImpl {

	String label;
	DateTime created;
	
	public OpenUnisonAuthenticator(
			String label,
            @NonNull AttestedCredentialData attestedCredentialData,
            @NonNull AttestationStatement attestationStatement,
            long counter,
            @Nullable Set<AuthenticatorTransport> transports,
            @Nullable AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions,
            @Nullable AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> authenticatorExtensions) {
        super(attestedCredentialData, attestationStatement, counter, transports,clientExtensions,authenticatorExtensions);
        this.label = label;
        this.created = DateTime.now();
        
    }

    public OpenUnisonAuthenticator(
    		String label,
            @NonNull AttestedCredentialData attestedCredentialData,
            @NonNull AttestationStatement attestationStatement,
            long counter,
            @Nullable Set<AuthenticatorTransport> transports) {
        super(attestedCredentialData,attestationStatement,counter,transports);
        
        this.label = label;
        this.created = DateTime.now();
    }

    public OpenUnisonAuthenticator(
    		String label,
            @NonNull AttestedCredentialData attestedCredentialData,
            @NonNull AttestationStatement attestationStatement,
            long counter) {
        super(attestedCredentialData,attestationStatement,counter);
        
        this.label = label;
        this.created = DateTime.now();
    }

	public String getLabel() {
		return label;
	}

	public DateTime getCreated() {
		return created;
	}
	
	

}
