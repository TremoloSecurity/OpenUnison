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


package com.tremolosecurity.json;
import java.util.ArrayList;
import java.util.List;



import org.joda.time.DateTime;

import com.tremolosecurity.saml.Attribute;


public class Request {
	String id;
	String notBefore;
	String notAfter;
	String uri;
	int loginLevel;
	String authChain;
	
	List<Attribute> attrs;
	
	public Request() {
		this.attrs = new ArrayList<Attribute>();
	}
	
	public String getId() {
		return id;
	}
	public void setId(String id) {
		this.id = id;
	}
	public String getNotBefore() {
		return notBefore;
	}
	public void setNotBefore(String notBefore) {
		this.notBefore = notBefore;
	}
	public String getNotAfter() {
		return notAfter;
	}
	public void setNotAfter(String notAfter) {
		this.notAfter = notAfter;
	}
	public String getUri() {
		return uri;
	}
	public void setUri(String uri) {
		this.uri = uri;
	}
	public List<Attribute> getAttrs() {
		return attrs;
	}
	public void setAttrs(List<Attribute> attrs) {
		this.attrs = attrs;
	}
	
	public int getLoginLevel() {
		return loginLevel;
	}

	public void setLoginLevel(int loginLevel) {
		this.loginLevel = loginLevel;
	}

	public String getAuthChain() {
		return authChain;
	}

	public void setAuthChain(String authChain) {
		this.authChain = authChain;
	}
	
}
