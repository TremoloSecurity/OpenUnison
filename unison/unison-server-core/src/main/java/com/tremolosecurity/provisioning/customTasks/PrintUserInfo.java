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

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;

public class PrintUserInfo implements CustomTask {

	/**
	 * 
	 */
	private static final long serialVersionUID = 6156946704893536650L;

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(PrintUserInfo.class.getName());
	
	transient WorkflowTask task;
	String msg;
	
	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params)
			throws ProvisioningException {
		Attribute attr = params.get("message");
		if (attr == null) {
			msg = null;
		} else {
			msg = attr.getValues().get(0);
		}
		
		this.task = task;

	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
		this.task = task;

	}

	@Override
	public boolean doTask(User user, Map<String, Object> request)
			throws ProvisioningException {
		
		if (this.msg != null) {
			logger.info(msg + " - " + user.getUserID() + " - " + user.getAttribs() + " / " + user.getGroups());
		} else {
			logger.info(user.getUserID() + " - " + user.getAttribs() + " / " + user.getGroups());
		}
		
		return true;
	}

}
