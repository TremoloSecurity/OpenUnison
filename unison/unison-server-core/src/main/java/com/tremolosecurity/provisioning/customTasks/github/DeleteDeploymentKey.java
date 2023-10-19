/*******************************************************************************
 * Copyright 2023 Tremolo Security, Inc.
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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpClient.Version;
import java.net.http.HttpResponse.BodyHandlers;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.jose4j.lang.JoseException;
import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;
import org.kohsuke.github.GHDeployKey;
import org.kohsuke.github.GHOrganization;
import org.kohsuke.github.GHRepository;

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

public class DeleteDeploymentKey implements CustomTask {
	
	String targetName;
	String repo;
	String keyLabel;
	
	transient WorkflowTask task;
	
	static Logger logger = Logger.getLogger(DeleteDeploymentKey.class);
	
	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
		this.task = task;
		
		this.targetName = params.get("targetName").getValues().get(0);
		this.repo = params.get("repo").getValues().get(0);
		
		this.keyLabel = params.get("keyLabel").getValues().get(0);
		
		

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
		if (workflow == null) {
			workflow = task.getWorkflow();
			request.put("WORKFLOW", workflow);
		}

		String localRepo = task.renderTemplate(this.repo, request);
		String localLabel = task.renderTemplate(this.keyLabel, request);
		
		String lTargetName = task.renderTemplate(targetName, request);
		ProvisioningTarget target = task.getConfigManager().getProvisioningEngine().getTarget(lTargetName);
		
		if (target == null) {
			throw new ProvisioningException(lTargetName + " does not exist");
		}
		
		if (! (target.getProvider() instanceof GitHubProvider)) {
			throw new ProvisioningException(lTargetName + " is not an instance of GitHubProvider");
		}
		
		GitHubProvider github = (GitHubProvider) target.getProvider();
		GHOrganization ghOrg = github.getOrganization();
		
		GHRepository repo;
		GHDeployKey foundKey = null;
		
		boolean found = false;
		
		try {
			repo = ghOrg.getRepository(localRepo);
			
			if (repo == null) {
				throw new ProvisioningException(String.format("target %s does not have repo %s", lTargetName,localRepo));
			}
			
			
			
			
			List<GHDeployKey> deployKeys = repo.getDeployKeys();
			
			for (GHDeployKey key : deployKeys) {
				if (key.getTitle().equals(localLabel)) {
					found = true;
					foundKey = key;
					break;
				}
			}
		} catch (IOException e1) {
			throw new ProvisioningException(String.format("Could not load keys %s in %s/%s", localLabel,github.getOrgName(),localRepo));
		}
		
		
		
		if (found) {
			
			
			deleteKey(github.getOrgName(),localRepo,github,lTargetName,approvalID,workflow,foundKey);

		
		
		} else {
			logger.warn(String.format("deployment key %s in %s/%s does not exist", localLabel,github.getOrgName(),localRepo));
		}
		
		return true;
	}
	
	private void deleteKey(String org,String repo,GitHubProvider github,String targetName,int approvalID,Workflow workflow, GHDeployKey deployKey) throws ProvisioningException {
		
		
		
		
		HttpRequest request;
		try {
			request = HttpRequest.newBuilder()
					  .uri(new URI(String.format("%s/repos/%s/%s/keys/%s", github.getApiHost(),github.getOrgName(),repo,deployKey.getId())))
					  .header("Authorization", String.format("Bearer %s", github.getToken()))
					  .DELETE()
					  .build();
			HttpClient client = HttpClient.newBuilder()
			        .version(Version.HTTP_1_1).build();
			HttpResponse<String> response = client.send(request, BodyHandlers.ofString());
			
			if (response.statusCode() != 204) {
				throw new ProvisioningException(String.format("Could not delete %s key in %s/%s: %d / %s", deployKey.getId(), org,repo,response.statusCode(),response.body()));
			}
			
			GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().logAction(targetName,
					false, ActionType.Delete, approvalID, workflow,
					String.format("github-repo-%s.%s-deploykey",github.getOrgName(),repo), deployKey.getTitle());
			
			
		} catch (URISyntaxException | JoseException | IOException | ProvisioningException | ParseException | InterruptedException e) {
			throw new ProvisioningException(String.format("Could not create key %s/%s",org,repo),e);
		}
	}

}
