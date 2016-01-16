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


package com.tremolosecurity.provisioning.core;

import com.novell.ldap.LDAPException;

public class ProvisioningException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 8819278660712940488L;
	boolean printStackTrace;
	
	/**
	 * 
	 */
	

	public ProvisioningException(String msg) {
		super(msg);
	}

	public ProvisioningException(String string, Throwable t) {
		super(string,t);
	}

	public boolean isPrintStackTrace() {
		return printStackTrace;
	}

	public void setPrintStackTrace(boolean printStackTrace) {
		this.printStackTrace = printStackTrace;
	}
	
	

}
