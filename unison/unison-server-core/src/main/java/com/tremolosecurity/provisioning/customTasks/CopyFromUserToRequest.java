/*******************************************************************************
 * Copyright 2017 Tremolo Security, Inc.
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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;

public class CopyFromUserToRequest implements CustomTask {
	Set<String> attributes;
	boolean keepInUser;
	transient WorkflowTask task;
	
	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
		this.task = task;
		
		this.attributes = new HashSet<String>();
		for (String attr : params.get("attribute").getValues()) {
			this.attributes.add(attr.toLowerCase());
		}
		
		this.keepInUser = params.get("keepInUser").getValues().get(0).equalsIgnoreCase("true");

	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
		this.task = task;

	}

	@Override
	public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {
		List<String> torm = new ArrayList<String>();
		
		for (String attrName : user.getAttribs().keySet()) {
			if (this.attributes.contains(attrName.toLowerCase())) {
				request.put(attrName, user.getAttribs().get(attrName).getValues().get(0));
				torm.add(attrName);
			}
		}
		
		if (! this.keepInUser) {
			for (String name : torm) {
				user.getAttribs().remove(name);
			}
		}

		return true;
	}

}
