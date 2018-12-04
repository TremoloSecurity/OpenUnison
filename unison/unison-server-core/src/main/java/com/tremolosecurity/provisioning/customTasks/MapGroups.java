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
import java.util.HashMap;
import java.util.Map;

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;

public class MapGroups implements CustomTask {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(MapGroups.class.getName()); 
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	Map<String,String> groupMap;
	
	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params)
			throws ProvisioningException {
		this.groupMap = new HashMap<String,String>();
		Attribute map = params.get("map");
		for (String mapping : map.getValues()) {
			String target = mapping.substring(0,mapping.indexOf('='));
			String source = mapping.substring(mapping.indexOf('=') + 1);
			this.groupMap.put(source, target);
		}
		
		
		

	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
		

	}

	@Override
	public boolean doTask(User user, Map<String, Object> request)
			throws ProvisioningException {
		
		ArrayList<String> toRm = new ArrayList<String>();
		ArrayList<String> toAdd = new ArrayList<String>();
		
		for (String groupName : user.getGroups()) {
			
		
			
			if (this.groupMap.containsKey(groupName)) {
		
				toRm.add(groupName);
				toAdd.add(this.groupMap.get(groupName));
			}
		}
		
		user.getGroups().removeAll(toRm);
		user.getGroups().addAll(toAdd);
		
		
		
		return true;
	}

}
