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

import java.io.UnsupportedEncodingException;
import java.util.Collections;
import java.util.Set;

import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;
import org.joda.time.DateTime;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.util.Base64Util;

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
    
    public static OpenUnisonAuthenticator deserialize(JSONObject root) throws ParseException {
    	byte[] bytes;
    	ObjectConverter objConverter = new ObjectConverter();
    	
    	bytes = Base64Util.decode((String) root.get("attestedCredentialData"));
    	AttestedCredentialDataConverter attestedCredentialDataConverter = new AttestedCredentialDataConverter(new ObjectConverter());
    	AttestedCredentialData attestedCredentialData = attestedCredentialDataConverter.convert(bytes);
    	
    	
    	bytes = Base64Util.decode((String) root.get("attestationStatement"));
    	AttestationStatementEnvelope deserializedEnvelope = objConverter.getCborConverter().readValue(bytes, AttestationStatementEnvelope.class);
    	AttestationStatement deserializedAttestationStatement = deserializedEnvelope.getAttestationStatement();
    	
    	
    	return new OpenUnisonAuthenticator(
    			(String) root.get("label"),
    			attestedCredentialData,
    			deserializedAttestationStatement,
    			(Long) root.get("counter")
    			);
    	
    }

	public String getLabel() {
		return label;
	}

	public DateTime getCreated() {
		return created;
	}
	
	
	
	
	public JSONObject serialize() {
		JSONObject serialized = new JSONObject();
		
		serialized.put("label", this.label);
		serialized.put("counter", this.getCounter());
		
		
		AttestedCredentialDataConverter attestedCredentialDataConverter = new AttestedCredentialDataConverter(new ObjectConverter()); 
		byte[] bytes = attestedCredentialDataConverter.convert(this.getAttestedCredentialData());
		serialized.put("attestedCredentialData", Base64Util.encodeToString(bytes));
		
		
		ObjectConverter objConverter = new ObjectConverter();
		AttestationStatementEnvelope envelope = new AttestationStatementEnvelope(this.getAttestationStatement());
		bytes = objConverter.getCborConverter().writeValueAsBytes(envelope);
		serialized.put("attestationStatement", Base64Util.encodeToString(bytes));
		
		return serialized;
		
		
	}
	
	

}
