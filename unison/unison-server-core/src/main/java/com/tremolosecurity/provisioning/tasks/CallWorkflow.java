/*******************************************************************************
 * Copyright 2020 Tremolo Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package com.tremolosecurity.provisioning.tasks;

import java.util.ArrayList;
import java.util.Map;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.CallWorkflowType;
import com.tremolosecurity.config.xml.WorkflowTaskType;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.core.WorkflowTaskImpl;

public class CallWorkflow extends WorkflowTaskImpl {

	String workflowName;
	
	@Override
	public String getLabel() {
		StringBuilder sb = new StringBuilder();
		sb.append("Call workflow ").append(this.workflowName);
		return sb.toString();
	}

	@Override
	public void init(WorkflowTaskType taskConfig) throws ProvisioningException {
		this.workflowName = ((CallWorkflowType) taskConfig).getName();
		
	}

	@Override
	public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {
		Workflow toCall = super.getConfigManager().getProvisioningEngine().getWorkflowCopy(this.workflowName);
		if (toCall == null) {
			throw new ProvisioningException("workflow '" + this.workflowName + "' does not exist");
		}
		
		ArrayList<WorkflowTask> tasksFromWf = toCall.getTasks();
		
		for (WorkflowTask task : tasksFromWf) {
			task.reInit(getConfigManager(), getWorkflow());
		}
		
		//this.getOnSuccess().addAll(toCall.getTasks());
		boolean doContinue = super.runSubTasks(toCall.getTasks(), user, request);
		return doContinue;
	}
	
public CallWorkflow() {
		
	}
	
	public CallWorkflow(WorkflowTaskType taskConfig, ConfigManager cfg,Workflow wf)
			throws ProvisioningException {
		super(taskConfig, cfg,wf);
		
	}

}
