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

import java.util.Map;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.ProvisionType;
import com.tremolosecurity.config.xml.WorkflowTaskType;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.ProvisioningTarget;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.WorkflowTaskImpl;
import com.tremolosecurity.provisioning.mapping.MapIdentity;

public class Provision extends WorkflowTaskImpl {

	
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 5617141018935769531L;
	transient private ProvisioningTarget target;
	boolean isSync;
	boolean setPassword;
	String targetName;
	
	public Provision() {
		
	}
	
	public Provision(WorkflowTaskType taskConfig, ConfigManager cfg,Workflow wf)
			throws ProvisioningException {
		super(taskConfig, cfg,wf);
		
		
		
		
	}

	@Override
	public void init(WorkflowTaskType taskConfig) throws ProvisioningException {
		ProvisionType provTskCfg = (ProvisionType) taskConfig;
		
		
		this.target = this.getConfigManager().getProvisioningEngine().getTarget(provTskCfg.getTarget());
		this.targetName = provTskCfg.getTarget();
		this.isSync = provTskCfg.isSync();
		this.setPassword = provTskCfg.isSetPassword();
	}
	
	

	@Override
	public void reInit() throws ProvisioningException  {
		this.target = this.getConfigManager().getProvisioningEngine().getTarget(this.targetName);
	}

	@Override
	public boolean doTask(User user,Map<String,Object> request) throws ProvisioningException {
		
		
		request.put("WORKFLOW", this.getWorkflow());
		/*if (this.isSync) {
			this.target.syncUser(user, false);
		} else {
			this.target.createUser(user);
		}*/
		
		this.target.syncUser(user, ! this.isSync,request);
		
		if (this.setPassword) {
			this.target.setPassword(user,request);
		}
		
		return true;
	}

	@Override
	public String getLabel() {
		StringBuffer b = new StringBuffer();
		b.append("Provision to ").append(this.targetName);
		return b.toString();
	}

	public boolean isSync() {
		return isSync;
	}

	public void setSync(boolean isSync) {
		this.isSync = isSync;
	}

	public boolean isSetPassword() {
		return setPassword;
	}

	public void setSetPassword(boolean setPassword) {
		this.setPassword = setPassword;
	}

	public String getTargetName() {
		return targetName;
	}

	public void setTargetName(String targetName) {
		this.targetName = targetName;
	}
	
	

}
