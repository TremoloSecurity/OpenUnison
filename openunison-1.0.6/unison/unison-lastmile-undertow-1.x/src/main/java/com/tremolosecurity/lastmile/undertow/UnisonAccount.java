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


package com.tremolosecurity.lastmile.undertow;

import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

import org.jboss.remoting3.security.UserPrincipal;
import org.jboss.security.SimplePrincipal;

import com.tremolosecurity.saml.Attribute;

import io.undertow.security.idm.Account;

public class UnisonAccount implements Account {

	Principal principal;
	String uid;
	Set<String> roles;
	
	public UnisonAccount(String uid,Attribute userRoles) {
		this.uid = uid;
		this.roles = new HashSet<String>();
		if (userRoles != null) {
			this.roles.addAll(userRoles.getValues());
		}
		this.principal = new SimplePrincipal(uid);
	}
	
	@Override
	public Principal getPrincipal() {
		return this.principal;
	}

	@Override
	public Set<String> getRoles() {
		return this.roles;
	}

}
