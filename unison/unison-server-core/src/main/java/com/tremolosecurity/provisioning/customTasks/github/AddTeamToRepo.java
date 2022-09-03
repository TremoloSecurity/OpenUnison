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

import org.kohsuke.github.GHOrganization;
import org.kohsuke.github.GHRepository;
import org.kohsuke.github.GHTeam;
import org.kohsuke.github.GHOrganization.RepositoryRole;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.ProvisioningTarget;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.provisioning.core.providers.GitHubProvider;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;

public class AddTeamToRepo implements CustomTask {
	
	transient WorkflowTask task;
	
	String teamName;
	String targetName;
	String repoName;
	String permission;
	

	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
		this.task = task;
		this.teamName = params.get("teamName").getValues().get(0);
		this.repoName = params.get("repoName").getValues().get(0);
		this.permission = params.get("permission").getValues().get(0);
		this.targetName = params.get("targetName").getValues().get(0);
	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
		this.task = task;

	}

	@Override
	public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {
		String ltargetname = task.renderTemplate(targetName, request);
		String lrepoName = task.renderTemplate(repoName, request);
		String lpermission = task.renderTemplate(permission, request);
		String lteamname = task.renderTemplate(teamName, request);
		
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}

		Workflow workflow = (Workflow) request.get("WORKFLOW");
		

		
		ProvisioningTarget userProvider = task.getConfigManager().getProvisioningEngine().getTarget(ltargetname);
		
		if (userProvider == null) {
			throw new ProvisioningException(String.format("Target %s does not exist", ltargetname));
		}
		
		if (! (userProvider.getProvider() instanceof com.tremolosecurity.provisioning.core.providers.GitHubProvider)) {
			throw new ProvisioningException(String.format("Target %s is not a GitHubProvider", ltargetname));
		}
		
		GitHubProvider ghTarget = (GitHubProvider) userProvider.getProvider();
		
		GHOrganization ghorg = ghTarget.getOrganization();
		
		GHTeam team;
		try {
			team = ghorg.getTeamByName(lteamname);
			if (team == null) {
				throw new ProvisioningException(String.format("Team %s does not exist", lteamname));
			}
		} catch (IOException e) {
			throw new ProvisioningException(String.format("Could not load team %s", lteamname),e);
		}
		GHRepository repo ;
		
		try {
			repo = ghorg.getRepository(lrepoName);
			
			if (repo == null) {
				throw new ProvisioningException(String.format("Could not load repo %s", lrepoName));
			}
		} catch (IOException e) {
			throw new ProvisioningException(String.format("Could not load repo %s", lrepoName),e);
		}
		
		try {
			team.add(repo, RepositoryRole.custom(lpermission));
		} catch (IOException e) {
			throw new ProvisioningException(String.format("Could not add permission %s to repo %s with team %s",lpermission,lrepoName,lteamname));
		}
		
		GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().logAction(this.targetName,
				false, ActionType.Add, approvalID, workflow,
				"github-permission-" + ghTarget.getOrgName() + "." + lrepoName + "-team", lteamname + "/" + lpermission );
		
		return true;
	}

}
