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
import org.gitlab4j.api.models.RepositoryFile;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.gitlab.provisioning.targets.GitlabUserProvider;

public class CreateGitFile implements CustomTask {
	
	String path;
	String targetName;
	String content;
	String branch;
	String project;
	String namespace;
	String commitMessage;
	
	transient WorkflowTask task;

	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
		this.task = task;
		
		this.targetName = params.get("targetName").getValues().get(0);
		this.namespace = params.get("namespace").getValues().get(0);
		this.project = params.get("project").getValues().get(0);
		this.branch = params.get("branch").getValues().get(0);
		this.path = params.get("path").getValues().get(0);
		this.content = params.get("content").getValues().get(0);
		this.commitMessage = params.get("commitMessage").getValues().get(0);

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
		String localPath = task.renderTemplate(this.path, request);
		String localBranch = task.renderTemplate(this.branch, request);
		String localContent = task.renderTemplate(this.content, request);
		String localCommit = task.renderTemplate(this.commitMessage, request);
		
		
		try {
			Project existingProject = api.getProjectApi().getProject(localNamespace, localProjectName);
			RepositoryFile rf = new RepositoryFile();
			rf.setFilePath(localPath);
			rf.setContent(localContent);
			RepositoryFile result = api.getRepositoryFileApi().createFile(existingProject, rf, localBranch, localCommit);
		
			GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().logAction(gitlab.getName(),
					false, ActionType.Add, approvalID, workflow,
					"gitlab-file-" + existingProject.getNameWithNamespace() + "-file", localPath + " / " + result.getCommitId());
			
		} catch (GitLabApiException e) {
			throw new ProvisioningException("Error looking up project " + localNamespace + "/" + localProjectName,e);
		}
		

		return true;
	}

}
