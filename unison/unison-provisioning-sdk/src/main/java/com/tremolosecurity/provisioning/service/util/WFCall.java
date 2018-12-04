/*
Copyright 2015, 2016 Tremolo Security, Inc.

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


package com.tremolosecurity.provisioning.service.util;

import java.util.HashMap;
import java.util.Map;

public class WFCall {
	String requestor;
	String name;
	String uidAttributeName;
	TremoloUser user;
	String reason;
	Map<String,Object> requestParams;
	String encryptedParams;
	
	
	public WFCall() {
		this.requestParams = new HashMap<String,Object>();
	}
	
	
	
	public Map<String, Object> getRequestParams() {
		return requestParams;
	}



	public void setRequestParams(Map<String, Object> requestParams) {
		this.requestParams = requestParams;
	}



	public String getReason() {
		return reason;
	}
	public void setReason(String reason) {
		this.reason = reason;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public String getUidAttributeName() {
		return uidAttributeName;
	}
	public void setUidAttributeName(String uidAttributeName) {
		this.uidAttributeName = uidAttributeName;
	}
	public TremoloUser getUser() {
		return user;
	}
	public void setUser(TremoloUser user) {
		this.user = user;
	}



	public String getRequestor() {
		return requestor;
	}



	public void setRequestor(String requestor) {
		this.requestor = requestor;
	}



	public String getEncryptedParams() {
		return encryptedParams;
	}



	public void setEncryptedParams(String encryptedParams) {
		this.encryptedParams = encryptedParams;
	}
	
	
	
	
}
