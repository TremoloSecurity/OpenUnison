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
package com.tremolosecurity.provisioning.tasks;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import com.tremolosecurity.git.GitUtils;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;
import com.tremolosecurity.provisioning.tasks.dataobj.GitFile;

public class PushToGit implements CustomTask {

	String secretName;
	String nameSpace;
	String target;
	String keyName;
	String gitRepo;
	String requestObject;
	String commitMsg;
	
	transient WorkflowTask task;
	
	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
		this.task = task;
		
		this.secretName = params.get("secretName").getValues().get(0);
		this.nameSpace = params.get("nameSpace").getValues().get(0);
		this.target = params.get("target").getValues().get(0);
		this.keyName = params.get("keyName").getValues().get(0);
		this.gitRepo = params.get("gitRepo").getValues().get(0);
		this.requestObject = params.get("requestObject").getValues().get(0);
		this.commitMsg = params.get("commitMsg").getValues().get(0);
		

	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
		this.task = task;

	}

	@Override
	public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {
		String localSecretName = task.renderTemplate(secretName, request);
		String localNameSpace = task.renderTemplate(nameSpace, request);
		String localTarget = task.renderTemplate(this.target, request);
		String localKeyName = task.renderTemplate(this.keyName, request);
		String localGitRepo = task.renderTemplate(gitRepo, request);
		String localCommitMsg = task.renderTemplate(commitMsg, request);
		
		OpenShiftTarget target = (OpenShiftTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(localTarget).getProvider();
		
		HttpCon con = null;
		
		GitUtils gitUtil = null;
		
		try {
			con = target.createClient();
			StringBuilder sb = new StringBuilder();
			sb.append("/api/v1/namespaces/").append(localNameSpace).append("/secrets/").append(localSecretName);
			String json = target.callWS(target.getAuthToken(), con, sb.toString());
			
			JSONObject secret = (JSONObject) new JSONParser().parse(json);
			
			JSONObject data = (JSONObject) secret.get("data");
			if (data == null) {
				throw new Exception("No data found for " + sb.toString());
			}
			
			String b64KeyData = (String) data.get(localKeyName);
			
			if (b64KeyData == null) {
				throw new ProvisioningException("Could not find key '" + localKeyName + "' in '" + sb.toString() + "'");
			}
			
			String privateKey = new String(java.util.Base64.getDecoder().decode(b64KeyData));
			
			gitUtil = new GitUtils(localGitRepo,privateKey);
			
			
			try {
				gitUtil.checkOut();
			} catch (Exception e) {
				throw new Exception("Could not checkout repo");
			}
			
			List<GitFile> files = (List<GitFile>) request.get(requestObject);
			
			if (files == null) {
				throw new Exception("No gitfiles stored in '" + requestObject + "'");
			}
			
			gitUtil.applyFiles(files);
			
			gitUtil.commitAndPush(localCommitMsg);
			
			
			
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not push to git",e);
		} finally {
			if (con != null) {
				try {
					con.getHttp().close();
				} catch (IOException e) {
					
				}
				con.getBcm().close();
			}
			
			if (gitUtil != null) {
				gitUtil.cleanup();
			}
		}
		
		
		return true;
	}

}
