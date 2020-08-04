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
package com.tremolosecurity.argocd.tasks;

import java.io.IOException;
import java.util.Map;

import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.util.EntityUtils;

import com.google.gson.Gson;
import com.tremolosecurity.argocd.targets.ArgoCDTarget;
import com.tremolosecurity.argocd.tasks.obj.GitRepo;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;

public class CreateGitRepository implements CustomTask {
	
	String type;
	String name;
	String repoUrl;
	String sshPrivateKey;
	String target;
	
	transient WorkflowTask task;

	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
		this.type = params.get("type").getValues().get(0);
		this.name = params.get("name").getValues().get(0);
		this.repoUrl = params.get("repoUrl").getValues().get(0);
		this.sshPrivateKey = params.get("sshPrivateKey").getValues().get(0);
		this.target = params.get("target").getValues().get(0);
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
		
		String localType = task.renderTemplate(this.type, request);
		String localName = task.renderTemplate(this.name, request);
		String localRepoUrl = task.renderTemplate(this.repoUrl, request);
		String localSshPrivateKey = task.renderTemplate(this.sshPrivateKey, request);
		
		GitRepo repo = new GitRepo();
		repo.setType(localType);
		repo.setName(localName);
		repo.setRepo(localRepoUrl);
		repo.setSshPrivateKey(localSshPrivateKey);
		
		Gson gson = new Gson();
		
		String json = gson.toJson(repo);
		
		//System.out.println(json);
		
		ArgoCDTarget argo = (ArgoCDTarget) task.getConfigManager().getProvisioningEngine().getTarget(this.target).getProvider();
		
		HttpCon con = null;
		
		try {
			con = argo.createConnection();
			
			String url = new StringBuilder().append(argo.getUrl()).append("/api/v1/repositories").toString();
			HttpPost post = new HttpPost(url);
			StringEntity str = new StringEntity(json,ContentType.APPLICATION_JSON);
			post.setEntity(str);
			
			HttpResponse resp = con.getHttp().execute(post);
			
			json = EntityUtils.toString(resp.getEntity());
			
			if (resp.getStatusLine().getStatusCode() < 200 || resp.getStatusLine().getStatusCode() >= 300) {
				throw new ProvisioningException("Could not create repository - " + resp.getStatusLine().getStatusCode() + " / " + json);
			}
			
			task.getConfigManager().getProvisioningEngine().logAction(argo.getName(),true, ActionType.Add,  approvalID, workflow, localName,localRepoUrl );
			
		} catch (IOException e) {
			throw new ProvisioningException("Could not create repository",e);
		}  finally {
			if (con != null) {
				try {
					con.getHttp().close();
				} catch (IOException e) {
					
				}
				
				con.getBcm().close();
			}
		}
		
		return true;
	}

}
