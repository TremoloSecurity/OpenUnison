/*******************************************************************************
 * Copyright 2016 Tremolo Security, Inc.
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
package com.tremolosecurity.scalejs.helpers;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

import jakarta.servlet.http.HttpServletRequest;

import org.apache.logging.log4j.Logger;

import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.scalejs.sdk.UiDecisions;

public class FilterHelper implements UiDecisions {
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(FilterHelper.class.getName());

	Map<String,Set<String>> attributeCheck;
	
	List<String> allowedFilters;
	
	boolean applyToDelegation;
	boolean applyToPreApproval;
	
	@Override
	public void init(HashMap<String, Attribute> config) {
		Attribute allowedFilters = config.get("allowedFilters");
		this.allowedFilters = new ArrayList<String>();
		if (allowedFilters != null) {
			this.allowedFilters.addAll(allowedFilters.getValues());
		}
		
		
		Attribute attrCheck = config.get("filterMap");
		this.attributeCheck = new HashMap<String,Set<String>>();
		if (attrCheck != null) {
			for (String cfg : attrCheck.getValues()) {
				String filter = cfg.substring(0,cfg.lastIndexOf('='));
				String attrs = cfg.substring(cfg.lastIndexOf('=') + 1);
				StringTokenizer toker = new StringTokenizer(attrs,",",false);
				HashSet<String> attrNames = new HashSet<String>();
				while (toker.hasMoreTokens()) {
					attrNames.add(toker.nextToken());
				}
				this.attributeCheck.put(filter, attrNames);
			}
		}
		
		if (config.get("applyToDelegration") != null) {
			this.applyToDelegation = config.get("applyToDelegration").getValues().get(0).equalsIgnoreCase("true");
		} else {
			this.applyToDelegation = false;
		}
		
		if (config.get("applyToPreApproval") != null) {
			this.applyToPreApproval = config.get("applyToPreApproval").getValues().get(0).equalsIgnoreCase("true");
		} else {
			this.applyToPreApproval = false;
		}

	}

	@Override
	public boolean canEditUser(AuthInfo user, HttpServletRequest request) {
		LDAPEntry entry = user.createLDAPEntry();
		try {
			for (String filter : this.allowedFilters) {
				net.sourceforge.myvd.types.Filter f = new net.sourceforge.myvd.types.Filter(filter);
				if (f.getRoot().checkEntry(entry)) {
					return true;
				}
			}
		} catch (LDAPException e) {
			logger.warn("Could not check user",e);
		}
		
		return false;
	}

	@Override
	public Set<String> availableAttributes(AuthInfo user, HttpServletRequest request) {
		LDAPEntry entry = user.createLDAPEntry();
		try {
			for (String filter : this.attributeCheck.keySet()) {
				net.sourceforge.myvd.types.Filter f = new net.sourceforge.myvd.types.Filter(filter);
				if (f.getRoot().checkEntry(entry)) {
					HashSet<String> newAttrs = new HashSet<String>();
					newAttrs.addAll(this.attributeCheck.get(filter));
					return newAttrs;
				}
			}
		} catch (LDAPException e) {
			logger.warn("Could not check user",e);
		}
		
		return new HashSet<String>();
	}

	@Override
	public boolean canRequestForOthers(String workflowName, AuthInfo user, HttpServletRequest request) {
		
		if (this.applyToDelegation) {
			LDAPEntry entry = user.createLDAPEntry();
			try {
				for (String filter : this.allowedFilters) {
					net.sourceforge.myvd.types.Filter f = new net.sourceforge.myvd.types.Filter(filter);
					if (f.getRoot().checkEntry(entry)) {
						return true;
					}
				}
			} catch (LDAPException e) {
				logger.warn("Could not check user",e);
			}
			
			return false;
		} else {
			return false;
		}
	}

	@Override
	public boolean canPreApprove(String workflowName, AuthInfo user, HttpServletRequest request) {
		
		if (this.applyToPreApproval) {
			LDAPEntry entry = user.createLDAPEntry();
			try {
				for (String filter : this.allowedFilters) {
					net.sourceforge.myvd.types.Filter f = new net.sourceforge.myvd.types.Filter(filter);
					if (f.getRoot().checkEntry(entry)) {
						return true;
					}
				}
			} catch (LDAPException e) {
				logger.warn("Could not check user",e);
			}
			
			return false;
		} else {
			return false;
		}
	}

}
