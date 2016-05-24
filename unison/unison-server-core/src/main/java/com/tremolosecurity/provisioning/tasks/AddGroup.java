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

import org.stringtemplate.v4.ST;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.AddGroupType;
import com.tremolosecurity.config.xml.WorkflowTaskType;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.WorkflowTaskImpl;

public class AddGroup extends WorkflowTaskImpl {

	/**
	 * 
	 */
	private static final long serialVersionUID = -4528632593490038311L;
	String name;
	boolean remove;
	
	public AddGroup() {
		
	}
	
	public AddGroup(WorkflowTaskType taskConfig, ConfigManager cfg,Workflow wf)
			throws ProvisioningException {
		super(taskConfig, cfg,wf);
		
	}

	@Override
	public void init(WorkflowTaskType taskConfig) throws ProvisioningException {
		AddGroupType addGrpTpCfg = (AddGroupType) taskConfig;
		this.name = addGrpTpCfg.getName();
		this.remove = addGrpTpCfg.isRemove();
	}

	@Override
	public boolean doTask(User user,Map<String,Object> request) throws ProvisioningException {
		if (this.remove) {
			user.getGroups().remove(this.renderTemplate(name, request));
		} else {
			user.getGroups().add(this.renderTemplate(name, request));
		}
		return true;
	}

	@Override
	public String getLabel() {
		StringBuffer b = new StringBuffer();
		b.append("Add group ").append(this.name);
		return b.toString();
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

}
