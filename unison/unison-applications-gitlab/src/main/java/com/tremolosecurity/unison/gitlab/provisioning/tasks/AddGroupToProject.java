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

import org.apache.logging.log4j.Logger;
import org.gitlab4j.api.GitLabApi;
import org.gitlab4j.api.GitLabApiException;
import org.gitlab4j.api.models.AccessLevel;
import org.gitlab4j.api.models.Group;
import org.gitlab4j.api.models.Project;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.gitlab.provisioning.targets.GitlabUserProvider;

public class AddGroupToProject implements CustomTask {
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(AddGroupToProject.class.getName());
	
	String groupName;
	String accessLevel;
	String targetName;
	
	String projectName;
	String namespace;

	transient WorkflowTask task;
	
	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
		this.targetName = params.get("targetName").getValues().get(0);
		this.groupName = params.get("groupName").getValues().get(0);
		this.accessLevel = params.get("accessLevel").getValues().get(0);
		
		if (params.get("projectName") != null ) {
			this.projectName = params.get("projectName").getValues().get(0);
			this.namespace = params.get("namespace").getValues().get(0);
		}
		
		this.task = task;

	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
		this.task = task;

	}

	@Override
	public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {
		if (request.get("newProjectJSON") == null) {
			logger.warn("Project not created, skipping");
			return true;
		}
		
		String localGroupName = task.renderTemplate(this.groupName, request);
		
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}

		Workflow workflow = (Workflow) request.get("WORKFLOW");

		GitlabUserProvider gitlab = (GitlabUserProvider) GlobalEntries.getGlobalEntries().getConfigManager()
				.getProvisioningEngine().getTarget(this.targetName).getProvider();
		GitLabApi api = gitlab.getApi();
		
		
		
		ObjectMapper mapper = new ObjectMapper();
		Project newProject = null;
		
		
		if (this.projectName == null) {
			try {
				newProject = (Project) mapper.readValue((String) request.get("newProjectJSON"), Project.class);
			} catch (JsonProcessingException e) {
				throw new ProvisioningException("Could not parse",e);
			}
		} else {
			String localProjectName = task.renderTemplate(this.projectName, request);
			String localNamespace = task.renderTemplate(this.namespace, request);
			try {
				newProject = api.getProjectApi().getProject(localNamespace, localProjectName);
			} catch (GitLabApiException e) {
				throw new ProvisioningException("Could not find " + localNamespace + "/" + localProjectName,e);
			}
		}
		
		
        
		
        Group groupToAdd;
		try {
			groupToAdd = gitlab.findGroupByName(localGroupName);
			if (groupToAdd == null) {
	        	throw new ProvisioningException("Group " + localGroupName + " does not exist");
	        }
	        
	        api.getProjectApi().shareProject(newProject, groupToAdd.getId(), AccessLevel.valueOf(accessLevel), null);
		} catch (GitLabApiException e) {
			throw new ProvisioningException("Could not add group " + localGroupName + " to project " + newProject.getNameWithNamespace(),e);
		}
        
		GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().logAction(gitlab.getName(),
				false, ActionType.Add, approvalID, workflow,
				"gitlab-project-" + newProject.getNameWithNamespace() + "-group", localGroupName);
        
		return true;
	}

}
