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


package com.tremolosecurity.provisioning.customTasks;

import java.util.HashMap;
import java.util.Map;
import java.util.HashSet;

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;

public class JITIgnoreGroups implements CustomTask {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(JITIgnoreGroups.class.getName());
	transient WorkflowTask task;
	HashSet<String> groups;
	String targetName;
	
	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params)
			throws ProvisioningException {
		
		logger.info("Initializing");
		
		this.groups = new HashSet<String>();
		this.groups.addAll(params.get("groupName").getValues());
		
		this.targetName = params.get("targetName").getValues().get(0);
		
		this.task = task;
		
		logger.info("Initialied, Groups - " + this.groups + ", target - " + this.targetName);
		
		
	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
		this.task = task;

	}

	@Override
	public boolean doTask(User user, Map<String, Object> request)
			throws ProvisioningException {
	
		
		
		try {
			User looking = task.getConfigManager().getProvisioningEngine().getTarget(this.targetName).findUser(user.getUserID(), new HashMap<String,Object>());
			if (looking != null) {
				
				HashSet<String> curGroups = new HashSet<String>();
				curGroups.addAll(user.getGroups());
				
				HashSet<String> lookingGroups = new HashSet<String>();
				lookingGroups.addAll(looking.getGroups());
				
		
				
				for (String group : groups) {
					if (lookingGroups.contains(group) && ! curGroups.contains(group)) {
						user.getGroups().add(group);
					}
				}
				
		
				
			
			} 
		} catch (ProvisioningException pe) {
			//do nothing
			pe.printStackTrace();
		}
		
		
		
		return true;
	}

}
