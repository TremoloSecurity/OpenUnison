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

import java.util.ArrayList;
import java.util.Map;
import java.util.HashSet;

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;

public class FilterGroups implements CustomTask {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(FilterGroups.class.getName());
	HashSet<String> allowedGroups;
	
	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params)
			throws ProvisioningException {
		this.allowedGroups = new HashSet<String>();
		Attribute allows = params.get("name");
		for (String name : allows.getValues()) {
			this.allowedGroups.add(name);
		}

	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
		

	}

	@Override
	public boolean doTask(User user, Map<String, Object> request)
			throws ProvisioningException {
		
		
		
		ArrayList<String> torm = new ArrayList<String>();
		for (String groupName : user.getGroups()) {
			
			
			if (! this.allowedGroups.contains(groupName)) {
				
				torm.add(groupName);
			}
		}
		
		user.getGroups().removeAll(torm);
		
		
		return true;
	}

}
