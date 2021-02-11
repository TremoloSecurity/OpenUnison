/*******************************************************************************
 * Copyright 2020 Tremolo Security, Inc.
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
package com.tremolosecurity.provisioning.customTasks;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.UserStoreProvider;
import com.tremolosecurity.provisioning.core.UserStoreProviderWithAddGroup;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;

public class RemoveGroupFromStore implements CustomTask {
	
	static transient Logger logger = org.apache.logging.log4j.LogManager.getLogger(RemoveGroupFromStore.class.getName());

	List<String> names;

	String target;
	
	transient WorkflowTask task;
	
	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
		this.names = new ArrayList<String>(); 
			
		this.names.addAll(params.get("name").getValues());
				
				
		this.target = params.get("target").getValues().get(0);
		
		
		
		this.task = task;
	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
		this.task = task;

	}

	@Override
	public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {
		UserStoreProvider target =  task.getConfigManager().getProvisioningEngine().getTarget(this.target).getProvider();
		if (target instanceof UserStoreProviderWithAddGroup) {
			
			request.put("WORKFLOW", this.task.getWorkflow());
			
			
			
			for (String name : names) {
				if ( ((UserStoreProviderWithAddGroup)target).isGroupExists(task.renderTemplate(name, request), user, request)) {
					((UserStoreProviderWithAddGroup)target).deleteGroup(task.renderTemplate(name, request),user, request);
				}
			}
		} else {
			logger.warn("Target '" + this.target + "' can not delete groups");
		}
		return true;
	}

}
