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


package com.tremolosecurity.provisioning.core;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.WorkflowTaskType;


public interface WorkflowTask {

	public abstract void init(WorkflowTaskType taskConfig)
			throws ProvisioningException;

	public abstract boolean doTask(User user, Map<String, Object> request)
			throws ProvisioningException;

	public abstract void reInit() throws ProvisioningException;

	public abstract void reInit(ConfigManager cfgMgr, Workflow wf)
			throws ProvisioningException;

	public abstract void initWorkFlow() throws ProvisioningException;

	public abstract WorkflowTaskType getConfig();

	public abstract ConfigManager getConfigManager();

	public abstract void setConfigManager(ConfigManager mgr);

	public abstract Workflow getWorkflow();

	public abstract void setWorkflow(Workflow workflow);

	public abstract boolean isOnHold();

	public abstract void setOnHold(boolean isOnHold);

	public abstract boolean restartChildren() throws ProvisioningException;

	public abstract WorkflowTask findApprovalTask();

	public abstract ArrayList<WorkflowTask> getChildren();
	
	public abstract String getLabel();

}