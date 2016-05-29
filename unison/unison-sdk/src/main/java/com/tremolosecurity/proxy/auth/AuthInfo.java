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


package com.tremolosecurity.proxy.auth;

import java.io.Serializable;
import java.util.HashMap;

import org.apache.logging.log4j.Logger;


import com.tremolosecurity.saml.Attribute;

public class AuthInfo implements Serializable {
	
	


	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1938906765816583538L;


	



	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(AuthInfo.class);
	
	
	String userDN;
	String authMethod;
	String authChain;
	
	boolean authComplete;
	
	



	int authLevel;
	
	HashMap<String,Attribute> attribs;
	
	public AuthInfo() {
		this.attribs = new HashMap<String,Attribute>();
		this.authComplete = false;
	}
	
	public AuthInfo(String userDN,String authMethod,String authChain,int authLevel) {
		this.userDN = userDN;
		this.authMethod = authMethod;
		this.authChain = authChain;
		this.authLevel = authLevel;
		this.attribs = new HashMap<String,Attribute>();
	}
	
	
	
	public String getAuthChain() {
		return authChain;
	}
	
	
	public HashMap<String,Attribute> getAttribs() {
		return attribs;
	}
	public String getUserDN() {
		return userDN;
	}
	public String getAuthMethod() {
		return authMethod;
	}
	public int getAuthLevel() {
		return authLevel;
	}



	public void setUserDN(String dn) {
		this.userDN = dn;
		
	}

	public void setAuthMethod(String authMethod) {
		this.authMethod = authMethod;
	}



	public void setAuthChain(String authChain) {
		this.authChain = authChain;
	}



	public void setAuthLevel(int authLevel) {
		this.authLevel = authLevel;
	}



	public void setAttribs(HashMap<String, Attribute> attribs) {
		this.attribs = attribs;
	}
	
	public boolean isAuthComplete() {
		return authComplete;
	}

	public void setAuthComplete(boolean authComplete) {
		this.authComplete = authComplete;
	}
}
