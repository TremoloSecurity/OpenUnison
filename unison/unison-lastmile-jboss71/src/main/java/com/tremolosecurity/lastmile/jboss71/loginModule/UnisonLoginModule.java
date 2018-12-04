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


package com.tremolosecurity.lastmile.jboss71.loginModule;

import java.security.Principal;
import java.security.acl.Group;

import javax.security.auth.login.LoginException;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.servlet.http.HttpServletRequest;

import org.jboss.logging.Logger;
import org.jboss.security.SimpleGroup;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.spi.UsernamePasswordLoginModule;

import com.tremolosecurity.saml.Attribute;

public class UnisonLoginModule extends UsernamePasswordLoginModule {

	static org.apache.logging.log4j.Logger log = org.apache.logging.log4j.LogManager.getLogger(UnisonLoginModule.class.getName());
	
	@Override
	protected Principal getIdentity() {
		log.debug("Getting Identity");
		HttpServletRequest request = null;
		try {
			request = (HttpServletRequest) PolicyContext.getContext("javax.servlet.http.HttpServletRequest");
		} catch (PolicyContextException e) {
			log.error("Could not load HttpServletRequest", e);
			return null;
		}
		
		if (request == null) {
			return null;
		}
		
		return new SimplePrincipal((String) request.getAttribute("UNISON_USER"));
		
	}

	@Override
	protected String getUsersPassword() throws LoginException {
		log.debug("Retrieving Password");
		return "";
	}

	@Override
	protected Group[] getRoleSets() throws LoginException {
		log.debug("Retrieving Groups");
		
		HttpServletRequest request = null;
		try {
			request = (HttpServletRequest) PolicyContext.getContext("javax.servlet.http.HttpServletRequest");
		} catch (PolicyContextException e) {
			log.error("Could not load HttpServletRequest", e);
			return null;
		}
		
		if (request == null) {
			return null;
		}
		
		Attribute attr = (Attribute) request.getAttribute("UINSON_ROLES");
		SimpleGroup group = new SimpleGroup("Roles");
		if (attr != null) {
			
			for (String val : attr.getValues()) {
				group.addMember(new SimplePrincipal(val));
			}
			
			
			
		}
		
		if (log.isDebugEnabled()) {
			log.debug("Returning Groups : " + group);
		}
		
		return new Group[]{group};
		
	}

}
