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
import com.tremolosecurity.config.xml.IfNotUserExistsType;
import com.tremolosecurity.config.xml.ProvisionType;
import com.tremolosecurity.config.xml.WorkflowTaskType;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.ProvisioningTarget;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.WorkflowTaskImpl;

public class IfNotUserExists extends WorkflowTaskImpl {

	
	/**
	 * 
	 */
	private static final long serialVersionUID = -8596242192704516221L;
	/**
	 * 
	 */
	
	private transient ProvisioningTarget target;
	String attributeName;
	String targetName;
	
	public IfNotUserExists() {
		
	}
	
	public IfNotUserExists(WorkflowTaskType taskConfig, ConfigManager cfg,Workflow wf)
			throws ProvisioningException {
		super(taskConfig, cfg,wf);
		
	}

	@Override
	public void init(WorkflowTaskType taskConfig) throws ProvisioningException {
		IfNotUserExistsType provTskCfg = (IfNotUserExistsType) taskConfig;
		this.target = this.getConfigManager().getProvisioningEngine().getTarget(provTskCfg.getTarget());
		this.attributeName = provTskCfg.getUidAttribute();
		this.targetName = provTskCfg.getTarget();
	}
	

	@Override
	public void reInit() throws ProvisioningException {
		this.target = this.getConfigManager().getProvisioningEngine().getTarget(this.targetName);
	}

	@Override
	public boolean doTask(User user,Map<String,Object> request) throws ProvisioningException {
		String attr = user.getAttribs().get(this.attributeName).getValues().get(0);
		User toFind  = this.target.findUser(attr,request);
		if (toFind == null) {
			return super.runChildren(user,request);
		}
		
		return true;

	}

	@Override
	public boolean restartChildren() throws ProvisioningException {
		return super.restartChildren(this.getWorkflow().getUser(),this.getWorkflow().getRequest());
	}

	@Override
	public String getLabel() {
		StringBuffer b = new StringBuffer();
		b.append("If user does not exsit in ").append(this.targetName);
		return b.toString();
	}
}
