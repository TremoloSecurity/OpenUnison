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

import java.util.Map;

import com.goterl.lazysodium.exceptions.SodiumException;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.ProvisioningTarget;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.provisioning.core.providers.GitHubProvider;
import com.tremolosecurity.provisioning.customTasks.github.secrets.SecretManagement;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;

public class CreateSecret implements CustomTask {
	
	String name;
	String value;
	String targetName;
	String repoName;
	
	WorkflowTask task;

	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
		this.task = task;
		
		this.targetName = params.get("targetName").getValues().get(0);
		this.repoName = params.get("repoName").getValues().get(0);
		this.name = params.get("name").getValues().get(0);
		this.value = params.get("value").getValues().get(0);

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
		
		String ltarget = task.renderTemplate(this.targetName, request);
		String lrepoName = task.renderTemplate(this.repoName, request);
		String lname = task.renderTemplate(name, request);
		String lvalue = task.renderTemplate(value, request);
		
		ProvisioningTarget userProvider = task.getConfigManager().getProvisioningEngine().getTarget(ltarget);
		
		if (userProvider == null) {
			throw new ProvisioningException(String.format("Target %s does not exist", ltarget));
		}
		
		if (! (userProvider.getProvider() instanceof com.tremolosecurity.provisioning.core.providers.GitHubProvider)) {
			throw new ProvisioningException(String.format("Target %s is not a GitHubProvider", ltarget));
		}
		
		GitHubProvider ghTarget = (GitHubProvider) userProvider.getProvider();
		
		SecretManagement secrets = new SecretManagement(ghTarget);
		
		try {
			secrets.storeSecret(lrepoName, lname, lvalue);
			
			GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().logAction(targetName,
					false, ActionType.Add, approvalID, workflow,
					String.format("github-repo-%s.%s-secret",ghTarget.getOrgName(),lrepoName), lname);
		} catch (ProvisioningException | SodiumException e) {
			throw new ProvisioningException(String.format("Could not store secret %s in %s/%s",lname,ghTarget.getOrgName(),lrepoName),e);
		}
		
		return true;
		
	}

}
