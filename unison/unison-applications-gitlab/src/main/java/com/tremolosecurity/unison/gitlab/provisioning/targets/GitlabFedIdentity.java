/*******************************************************************************
 * Copyright 2020 Tremolo Security, Inc.
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
package com.tremolosecurity.unison.gitlab.provisioning.targets;

public class GitlabFedIdentity {
	String externalUid;
	String provider;
	int samleProviderId;
	
	public String getExternalUid() {
		return externalUid;
	}
	public void setExternalUid(String externalUid) {
		this.externalUid = externalUid;
	}
	public String getProvider() {
		return provider;
	}
	public void setProvider(String provider) {
		this.provider = provider;
	}
	public int getSamleProviderId() {
		return samleProviderId;
	}
	public void setSamleProviderId(int samleProviderId) {
		this.samleProviderId = samleProviderId;
	}
	
	
	
}
