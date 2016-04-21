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


package com.tremolosecurity.provisioning.tasks;

import java.util.HashMap;
import java.util.Map;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.IfAttrExistsType;
import com.tremolosecurity.config.xml.WorkflowTaskType;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.WorkflowTaskImpl;

public class IfAttrExists extends WorkflowTaskImpl {

	
	/**
	 * 
	 */
	private static final long serialVersionUID = 613615984240708622L;
	String name;
	
	public IfAttrExists() {
		
	}
	
	public IfAttrExists(WorkflowTaskType taskConfig, ConfigManager cfg,Workflow wf)
			throws ProvisioningException {
		super(taskConfig, cfg,wf);
		
	}

	@Override
	public void init(WorkflowTaskType taskConfig) throws ProvisioningException {
		IfAttrExistsType cfg = (IfAttrExistsType) taskConfig;
		this.name = cfg.getName();
		

	}

	@Override
	public boolean doTask(User user,Map<String,Object> request) throws ProvisioningException {
		
		String localName = this.renderTemplate(name, request);
		
		if (user.getAttribs().containsKey(localName)) {
			return super.runSubTasks(super.getOnSuccess(),user,request);
		} else {
			return super.runSubTasks(super.getOnFailure(),user,request);
		}

	}

	@Override
	public boolean restartChildren() throws ProvisioningException {
		return super.restartChildren(this.getWorkflow().getUser(),this.getWorkflow().getRequest());
	}

	@Override
	public String getLabel() {
		StringBuffer b = new StringBuffer();
		b.append("If user has attribute ").append(this.name);
		return b.toString();
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	
}
