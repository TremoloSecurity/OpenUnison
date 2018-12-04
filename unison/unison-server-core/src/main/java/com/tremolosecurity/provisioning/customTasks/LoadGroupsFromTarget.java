/*******************************************************************************
 * Copyright 2018 Tremolo Security, Inc.
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
package com.tremolosecurity.provisioning.customTasks;

import static org.apache.directory.ldap.client.api.search.FilterBuilder.equal;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import org.apache.log4j.Logger;

import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;

public class LoadGroupsFromTarget implements CustomTask {

	static transient org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(LoadGroupsFromTarget.class.getName());
	
	

	String nameAttr;
	boolean inverse;
	String target;
	transient ConfigManager cfg;
	
	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params)
			throws ProvisioningException {
		
		
		
		
		
		
		this.nameAttr = params.get("nameAttr").getValues().get(0);
		this.inverse = params.get("inverse") != null && params.get("inverse").getValues().get(0).equalsIgnoreCase("true"); 
		this.target = params.get("target").getValues().get(0);
		
		logger.info("Name Attribute : '" + this.nameAttr + "'");
		logger.info("Inverse : '" + this.inverse + "'");
		logger.info("Target : '" + this.target + "'");
		
		this.cfg = task.getConfigManager();

	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
		this.cfg = task.getConfigManager();

	}

	@Override
	public boolean doTask(User user, Map<String, Object> request)
			throws ProvisioningException {
		
		
		
		
		
		
		
		try {
			
			HashSet<String> currentGroups = new HashSet<String>();
			currentGroups.addAll(user.getGroups());
			if (logger.isDebugEnabled()) {
				logger.debug("Current Groups : '" + currentGroups + "'");
			}
			
			if (inverse) {
				user.getGroups().clear();
			}
			
			
			User fromTarget = this.cfg.getProvisioningEngine().getTarget(this.target).findUser(user.getAttribs().get(this.nameAttr).getValues().get(0), new HashMap<String,Object>());
			
			for (String groupName : fromTarget.getGroups()) {
				if (logger.isDebugEnabled()) {
					logger.debug("Group - " + groupName);
				}
				
				if (inverse) {
					if (! currentGroups.contains(groupName)) {
						if (logger.isDebugEnabled()) {
							logger.debug("Adding " + groupName);
						}
						user.getGroups().add(groupName);
					}
				} else {
					if (logger.isDebugEnabled()) {
						logger.debug("Adding " + groupName);
					}
					user.getGroups().add(groupName);
				}
			}
			
		
			if (logger.isDebugEnabled()) {
				logger.debug("New Groups : '" + user.getGroups() + "'");
			}
			
			
		} catch (ProvisioningException e) {
			throw new ProvisioningException("Could not load user : " + user.getUserID(),e);
		}
		
		
		return true;
	}

}
