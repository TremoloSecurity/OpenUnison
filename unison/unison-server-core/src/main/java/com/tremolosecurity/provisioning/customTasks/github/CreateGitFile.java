/*******************************************************************************
 * Copyright 2022 Tremolo Security, Inc.
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
package com.tremolosecurity.provisioning.customTasks.github;

import java.io.IOException;
import java.util.Map;


import org.kohsuke.github.GHBranch;
import org.kohsuke.github.GHContent;
import org.kohsuke.github.GHContentUpdateResponse;
import org.kohsuke.github.GHFileNotFoundException;
import org.kohsuke.github.GHOrganization;
import org.kohsuke.github.GHRepository;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.core.providers.GitHubProvider;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;


public class CreateGitFile implements CustomTask {
	
	String path;
	String targetName;
	String content;
	String branch;
	String repository;
	String commitMessage;
	
	transient WorkflowTask task;

	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
		this.task = task;
		
		this.targetName = params.get("targetName").getValues().get(0);
		this.repository = params.get("repository").getValues().get(0);
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

		GitHubProvider github = (GitHubProvider) GlobalEntries.getGlobalEntries().getConfigManager()
				.getProvisioningEngine().getTarget(this.targetName).getProvider();
		
		GHOrganization org = github.getOrganization();
		
		
		String localRepository = task.renderTemplate(this.repository, request);
		String localPath = task.renderTemplate(this.path, request);
		String localBranch = task.renderTemplate(this.branch, request);
		String localContent = task.renderTemplate(this.content, request);
		String localCommit = task.renderTemplate(this.commitMessage, request);
		
		
		try {
			
			GHRepository repo = org.getRepository(localRepository);
			
			if (repo == null) {
				throw new ProvisioningException(String.format("Repository %s does not exist", localRepository));
			}
			
			
			GHBranch repoBranch = repo.getBranch(localBranch);
			
			if (repoBranch == null) {
				throw new ProvisioningException(String.format("Repository %s does not have branch %s", localRepository,localBranch));
			}
			
			boolean found = false;
			try {
				GHContent file = repo.getFileContent(localPath, localBranch);
				found = true;
			} catch (GHFileNotFoundException e) {
				found = false;
			}
			
			if (! found) {
				GHContentUpdateResponse ghresp = repo.createContent()
				    .branch(localBranch)
				    .message(localCommit)
				    .content(localContent)
				    .path(localPath)
				    
				    .commit();
				
				GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().logAction(this.targetName,
						false, ActionType.Add, approvalID, workflow,
						"github-file-" + github.getOrgName() + "." + localRepository + "-file", localPath + " / " + ghresp.getCommit().getSha());
			}
			
		} catch (IOException e) {
			throw new ProvisioningException("Error updating " + github.getOrgName() + "." + localRepository,e);
		}
		

		return true;
	}

}
