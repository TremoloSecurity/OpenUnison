/*******************************************************************************
 * Copyright 2017 Tremolo Security, Inc.
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
package com.tremolosecurity.unison.google.u2f;

import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.google.u2f.server.DataStore;
import com.google.u2f.server.data.EnrollSessionData;
import com.google.u2f.server.data.SecurityKeyData;
import com.google.u2f.server.data.SignSessionData;

public class UnisonDataStore implements DataStore {

	EnrollSessionData sessionData;
	String sessionId;
	
	List<SecurityKeyData> securtiyKeyData;
	private HashSet<X509Certificate> attestationCerts;
	
	public UnisonDataStore(String sessionId,List<SecurityKeyData> securityKeyData,HashSet<X509Certificate> attestationCerts) {
		this.attestationCerts = attestationCerts;
		this.sessionId = sessionId;
		this.securtiyKeyData = securityKeyData;
	}
	
	public UnisonDataStore(String sessionId,List<SecurityKeyData> securityKeyData) {
		this.attestationCerts = new HashSet<X509Certificate>();
		this.sessionId = sessionId;
		this.securtiyKeyData = securityKeyData;
	}
	
	@Override
	public void addTrustedCertificate(X509Certificate certificate) {
		// do nothing

	}

	@Override
	public Set<X509Certificate> getTrustedCertificates() {
		
		return this.attestationCerts;
	}

	@Override
	public String storeSessionData(EnrollSessionData sessionData) {
		this.sessionData = sessionData;
		return this.sessionId;
	}

	@Override
	public SignSessionData getSignSessionData(String sessionId) {
		return (SignSessionData) this.sessionData;
	}

	@Override
	public EnrollSessionData getEnrollSessionData(String sessionId) {
		return this.sessionData;
	}

	@Override
	public void addSecurityKeyData(String accountName, SecurityKeyData securityKeyData) {
		this.securtiyKeyData.add(securityKeyData);

	}

	@Override
	public List<SecurityKeyData> getSecurityKeyData(String accountName) {
		return this.securtiyKeyData;
	}

	@Override
	public void removeSecurityKey(String accountName, byte[] publicKey) {
		SecurityKeyData torm = null;
		
		for (SecurityKeyData skd : this.securtiyKeyData) {
			if (skd.getPublicKey().equals(publicKey)) {
				torm = skd;
			}
		}
		
		if (torm != null) {
			this.securtiyKeyData.remove(torm);
		}

	}

	@Override
	public void updateSecurityKeyCounter(String accountName, byte[] publicKey, int newCounterValue) {
		SecurityKeyData toupdate = null;
		
		for (SecurityKeyData skd : this.securtiyKeyData) {
			if (skd.getPublicKey().equals(publicKey)) {
				toupdate = skd;
			}
		}
		
		if (toupdate != null) {
			toupdate.setCounter(newCounterValue);
		}

	}

}
