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
import com.tremolosecurity.config.xml.DeleteType;
import com.tremolosecurity.config.xml.ProvisionType;
import com.tremolosecurity.config.xml.WorkflowTaskType;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.ProvisioningTarget;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.WorkflowTaskImpl;

public class Delete extends WorkflowTaskImpl {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1450995303446838078L;
	
	String targetName;
	
	public Delete() {
		
	}
	
	public Delete(WorkflowTaskType taskConfig, ConfigManager cfg, Workflow wf)
			throws ProvisioningException {
		super(taskConfig, cfg, wf);
		
	}

	@Override
	public void init(WorkflowTaskType taskConfig) throws ProvisioningException {
		DeleteType delTskCfg = (DeleteType) taskConfig;
		this.targetName = delTskCfg.getTarget();
		

	}

	
	
	@Override
	public void reInit() throws ProvisioningException {
		
	}

	@Override
	public boolean doTask(User user, Map<String, Object> request)
			throws ProvisioningException {
		
		request.put("WORKFLOW", this.getWorkflow());
		ProvisioningTarget target = this.getConfigManager().getProvisioningEngine().getTarget(this.targetName);
		target.deleteUser(user, request);
		return true;
		
	}

	@Override
	public String getLabel() {
		StringBuffer b = new StringBuffer();
		b.append("Delete from ").append(this.targetName);
		return b.toString();
	}

	public String getTargetName() {
		return targetName;
	}

	public void setTargetName(String targetName) {
		this.targetName = targetName;
	}

}
