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


package com.tremolosecurity.proxy.auth;

import java.io.Serializable;
import java.util.HashMap;

import com.tremolosecurity.proxy.SessionManager;
import com.tremolosecurity.proxy.TremoloHttpSession;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.server.GlobalEntries;
import org.apache.logging.log4j.Logger;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPEntry;
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
	TremoloHttpSession session;
	



	int authLevel;
	
	HashMap<String,Attribute> attribs;
	
	public AuthInfo() {
		this.attribs = new HashMap<String,Attribute>();
		this.authComplete = false;


	}
//	public AuthInfo(String userDN, String authMethod, String authChain, int authLevel) {
//		this(userDN, authMethod, authChain, authLevel, null);
//	}
	public AuthInfo(String userDN, String authMethod, String authChain, int authLevel, TremoloHttpSession session) {
		this.userDN = userDN;
		this.authMethod = authMethod;
		this.authChain = authChain;
		this.authLevel = authLevel;
		this.attribs = new HashMap<String,Attribute>();
		if (session != null && authLevel != 0) {
			SessionManager sessionManager = (SessionManager) GlobalEntries.getGlobalEntries().get(ProxyConstants.TREMOLO_SESSION_MANAGER);
			this.session = session;
			this.session.setUserDN(userDN);
			sessionManager.addUserSession(userDN,session);
		}

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



	public void setUserDN(String dn,TremoloHttpSession session) {
		this.userDN = dn;

		if (session != null) {
			session.setUserDN(dn);
			SessionManager sessionManager = (SessionManager) GlobalEntries.getGlobalEntries().get(ProxyConstants.TREMOLO_SESSION_MANAGER);
			sessionManager.addUserSession(dn, session);
			sessionManager.removeUserSession(dn, session);
		}
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
	
	public LDAPEntry createLDAPEntry() {
		LDAPAttributeSet attrs = new LDAPAttributeSet();
		
		for (String name : this.attribs.keySet()) {
			Attribute attr = this.attribs.get(name);
			LDAPAttribute ldap = new LDAPAttribute(name);
			for (String val : attr.getValues()) {
				ldap.addValue(val);
			}
			attrs.add(ldap);
		}
		
		LDAPEntry entry = new LDAPEntry(this.userDN,attrs);
		return entry;
	}
}
