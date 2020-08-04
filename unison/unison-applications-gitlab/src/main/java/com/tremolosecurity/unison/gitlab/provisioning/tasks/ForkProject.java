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
package com.tremolosecurity.unison.gitlab.provisioning.tasks;

import java.util.Map;

import org.gitlab4j.api.GitLabApi;
import org.gitlab4j.api.GitLabApiException;
import org.gitlab4j.api.models.Project;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.gitlab.provisioning.targets.GitlabUserProvider;

public class ForkProject implements CustomTask {
	
	String sourceProjectName;
	String sourceProjectNamespace;
	String destintionNamespace;
	String targetName;
	
	transient WorkflowTask task;

	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
		this.sourceProjectName = params.get("sourceProjectName").getValues().get(0);
		this.sourceProjectNamespace = params.get("sourceProjectNamespace").getValues().get(0);
		this.destintionNamespace = params.get("destinationNamespace").getValues().get(0);
		this.targetName = params.get("targetName").getValues().get(0);
		this.task = task;

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

		String localSourceProjectNamespace = task.renderTemplate(this.sourceProjectNamespace, request);
		String localSourceProjectName = task.renderTemplate(this.sourceProjectName, request);
		String localDestinationNamespace = task.renderTemplate(this.destintionNamespace, request);
		
		try {
			Project existingProject = api.getProjectApi().getProject(localSourceProjectNamespace, localSourceProjectName);
			api.getProjectApi().forkProject(existingProject, localDestinationNamespace);
		
			GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().logAction(gitlab.getName(),
					false, ActionType.Add, approvalID, workflow,
					"gitlab-fork-" + existingProject.getNameWithNamespace() + "-fork", localDestinationNamespace);
			
		} catch (GitLabApiException e) {
			throw new ProvisioningException("Error looking up project " + localSourceProjectNamespace + "/" + localSourceProjectName,e);
		}
		
		
		return true;
	}

}
