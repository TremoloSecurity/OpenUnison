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
import java.util.List;

import com.google.u2f.server.data.SecurityKeyData.Transports;

public class KeyHolder {
	private long enrollmentTime;
	private List<Transports> transports;

	byte[] keyHandle;
	byte[] publicKey;

	private int counter;

	public long getEnrollmentTime() {
		return enrollmentTime;
	}

	public void setEnrollmentTime(long enrollmentTime) {
		this.enrollmentTime = enrollmentTime;
	}

	public List<Transports> getTransports() {
		return transports;
	}

	public void setTransports(List<Transports> transports) {
		this.transports = transports;
	}

	public byte[] getKeyHandle() {
		return keyHandle;
	}

	public void setKeyHandle(byte[] keyHandle) {
		this.keyHandle = keyHandle;
	}

	public byte[] getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(byte[] publicKey) {
		this.publicKey = publicKey;
	}

	public int getCounter() {
		return counter;
	}

	public void setCounter(int counter) {
		this.counter = counter;
	}

}
