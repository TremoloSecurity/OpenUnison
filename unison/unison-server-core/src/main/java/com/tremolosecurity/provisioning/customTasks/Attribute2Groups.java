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


package com.tremolosecurity.provisioning.customTasks;

import java.util.Map;

import org.apache.log4j.Logger;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;

public class Attribute2Groups implements CustomTask {

	static Logger logger = Logger.getLogger(Attribute2Groups.class.getName());
	
	transient WorkflowTask task;
	String attributeName;
	
	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params)
			throws ProvisioningException {
		Attribute attr = params.get("attributeName");
		if (attr == null) {
			throw new ProvisioningException("attributeName not specified");
		}
		
		this.attributeName = attr.getValues().get(0);
		
		this.task = task;

	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
		this.task = task;

	}

	@Override
	public boolean doTask(User user, Map<String, Object> request)
			throws ProvisioningException {
		
		Attribute groups = user.getAttribs().get(this.attributeName);
		if (groups == null) {
			StringBuffer b = new StringBuffer();
			b.append("Attribute '").append(this.attributeName).append("' not found");
			logger.warn(b.toString());
		} else {
			user.getGroups().addAll(groups.getValues());
			user.getAttribs().remove(this.attributeName);
		}
		
		return true;
	}



}
