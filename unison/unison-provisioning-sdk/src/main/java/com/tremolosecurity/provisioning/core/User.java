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


package com.tremolosecurity.provisioning.core;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.Logger;


import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.util.ByteArray;
import com.tremolosecurity.saml.Attribute;

public class User implements Serializable {
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(User.class);
	
	
	String userID;
	List<String> groups;
	
	boolean resync;
	boolean keepExternalAttrs;
	boolean JitAddToAuditDB;
	
	String password;
	
	String requestReason;
	
	Map<String,Attribute> attribs;
	
	public User() {
		this.attribs = new HashMap<String,Attribute>();
		this.groups = new ArrayList<String>();
		this.requestReason = "";
	}
	
	public User(LDAPEntry entry) {
		this();
		
		for (Object o : entry.getAttributeSet()) {
			LDAPAttribute attr = (LDAPAttribute) o;

			
			
			LinkedList<ByteArray> rawVals = attr.getAllValues();
			
			Attribute attrib = new Attribute(attr.getBaseName());
			
			for (ByteArray val : rawVals) {
				try {
					attrib.getValues().add(new String(val.getValue(),"UTF-8"));
				} catch (UnsupportedEncodingException e) {
					//ignore
				}
			}
			
			
			this.attribs.put(attrib.getName(),attrib);
			
		}
	}
	
	public String getPassword() {
		return password;
	}





	public void setPassword(String password) {
		this.password = password;
	}





	public boolean isResync() {
		return resync;
	}





	public void setResync(boolean resync) {
		this.resync = resync;
	}





	public boolean isKeepExternalAttrs() {
		return keepExternalAttrs;
	}





	public void setKeepExternalAttrs(boolean keepExternalAttrs) {
		this.keepExternalAttrs = keepExternalAttrs;
	}
	
	
	public User(String userID) {
		this();
		this.userID = userID;

		
	}
	
	
	
	
	
	public List<String> getGroups() {
		return groups;
	}





	public Map<String,Attribute> getAttribs() {
		return attribs;
	}
	public String getUserID() {
		return userID;
	}
	
	@Override
	public String toString() {
		String val = "---------------------\n";
		val += "user id : '" + this.userID + "'\n";
		for (String attrName : this.attribs.keySet()) {
			Attribute attr = this.attribs.get(attrName);
			for (String attrVal : attr.getValues()) {
				val += attrName + " : '" + attrVal + "'\n"; 
			}
		}
		
		for (String group : this.groups) {
			val += "group : '" + group + "'\n";
		}
		
		val += "---------------------\n";
		
		return val;
	}





	public void setUserID(String userID) {
		this.userID = userID;
	}

	public String getRequestReason() {
		return requestReason;
	}

	public void setRequestReason(String requestReason) {
		this.requestReason = requestReason;
	}

	public boolean isJitAddToAuditDB() {
		return JitAddToAuditDB;
	}

	public void setJitAddToAuditDB(boolean jitAddToAuditDB) {
		JitAddToAuditDB = jitAddToAuditDB;
	}
	
	
}
