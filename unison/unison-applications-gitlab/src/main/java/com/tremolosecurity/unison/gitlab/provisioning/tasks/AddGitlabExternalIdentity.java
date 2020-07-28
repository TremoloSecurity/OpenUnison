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

import java.util.ArrayList;
import java.util.Map;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.unison.gitlab.provisioning.targets.GitlabFedIdentity;
import com.tremolosecurity.unison.gitlab.provisioning.targets.GitlabUserProvider;

public class AddGitlabExternalIdentity implements CustomTask {

	String provider;
	String userAttribute;
	
	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
		this.provider = params.get("provider").getValues().get(0);
		this.userAttribute = params.get("userAttribute").getValues().get(0);

	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
		

	}

	@Override
	public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {
		
		String uidAttribute = user.getAttribs().get(this.userAttribute).getValues().get(0);
		
		GitlabFedIdentity idToCreate = new GitlabFedIdentity();
		idToCreate.setExternalUid(uidAttribute);
		idToCreate.setProvider(this.provider);
		
		ArrayList<GitlabFedIdentity> idsToCreate = new ArrayList<GitlabFedIdentity>();
		idsToCreate.add(idToCreate);
		
		request.put(GitlabUserProvider.GITLAB_IDENTITIES,idsToCreate);
		
		return true;
	}

}
