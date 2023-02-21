/*******************************************************************************
 * Copyright (c) 2023 Tremolo Security, Inc.
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
package com.tremolosecurity.unison.gitlab.provisioning.tasks;

import java.util.Map;

import org.apache.log4j.Logger;
import org.gitlab4j.api.GitLabApi;
import org.gitlab4j.api.GitLabApiException;
import org.gitlab4j.api.models.Variable;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.gitlab.provisioning.targets.GitlabUserProvider;

import net.bytebuddy.asm.Advice.This;

public class CreateVariable implements CustomTask {
	static Logger logger = Logger.getLogger(CreateVariable.class.getName());
	transient WorkflowTask task;
	
	String targetName;
	String namespace;
	String project;
	
	String key;
	String value;
	String varType;
	String protectedVar;
	String masked;
	String environment;
	
	
	
	
	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
		this.task = task;
		
		this.targetName = params.get("targetName").getValues().get(0);
		this.namespace = params.get("namespace").getValues().get(0);
		this.project = params.get("project").getValues().get(0);
		
		this.key = params.get("key").getValues().get(0);
		this.value = params.get("value").getValues().get(0);
		this.varType = params.get("varType").getValues().get(0);
		this.protectedVar = params.get("protectedVar").getValues().get(0);
		this.masked = params.get("masked").getValues().get(0);
		this.environment = params.get("environment").getValues().get(0);

	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
		this.task = task;

	}

	@Override
	public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}

		Workflow workflow = (Workflow) request.get("WORKFLOW");

		GitlabUserProvider gitlab = (GitlabUserProvider) GlobalEntries.getGlobalEntries().getConfigManager()
				.getProvisioningEngine().getTarget(this.targetName).getProvider();
		GitLabApi api = gitlab.getApi();
		
		String localNamespace = task.renderTemplate(this.namespace, request);
		String localProjectName = task.renderTemplate(this.project, request);
		
		String localKey = task.renderTemplate(this.key, request);
		String localValue = task.renderTemplate(this.value, request);
		
		String localVarType = task.renderTemplate(this.varType, request);
		Variable.Type localType = localVarType.equalsIgnoreCase("FILE") ? Variable.Type.FILE : Variable.Type.ENV_VAR;
		
		
		String localStrProtected = task.renderTemplate(this.protectedVar, request);
		boolean localProtected = localStrProtected.equalsIgnoreCase("true");
		
		String localStrMasked = task.renderTemplate(this.masked, request);
		boolean localMasked = localStrMasked.equalsIgnoreCase("true");
		
		String localEnvironment = task.renderTemplate(this.environment, request);
		
		try {
			api.getProjectApi().createVariable(localNamespace + "/" + localProjectName , localKey, localValue, localType, localProtected, localMasked, localEnvironment);
		} catch (GitLabApiException e) {
			throw new ProvisioningException(String.format("Could not create variable %s/%s.%s",localNamespace,localProjectName,localKey),e);
		}
		
		GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().logAction(gitlab.getName(),
				false, ActionType.Add, approvalID, workflow,
				"gitlab-project-" + localNamespace + "-" + localProjectName + "-variable", localKey);

		
		return true;
	}

}
