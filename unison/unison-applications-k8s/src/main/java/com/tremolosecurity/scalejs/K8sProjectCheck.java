/*******************************************************************************
 * Copyright 2019 Tremolo Security, Inc.
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
package com.tremolosecurity.scalejs;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import com.tremolosecurity.git.GitUtils;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.scalejs.register.cfg.ScaleJSRegisterConfig;
import com.tremolosecurity.scalejs.register.data.NewUserRequest;
import com.tremolosecurity.scalejs.register.sdk.CreateRegisterUser;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;

public class K8sProjectCheck implements CreateRegisterUser {

	static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(K8sProjectCheck.class);
	
	
	String workflowName;
	String targetName;
	String projectAttributeName;
	
	boolean checkIfExists;
	
	
	
	@Override
	public void init(ScaleJSRegisterConfig registerConfig) throws ProvisioningException {
		
		workflowName = registerConfig.getCustomSubmissionConfig().get("workflowName").getValues().get(0);
		
		logger.info("Workflow Name : '" + workflowName + "'");
		
		targetName = registerConfig.getCustomSubmissionConfig().get("targetName").getValues().get(0);
		
		logger.info("Target Name : '" + targetName + "'");
		
		projectAttributeName = registerConfig.getCustomSubmissionConfig().get("projectAttributeName").getValues().get(0);
		
		logger.info("Attribute Name : '" + projectAttributeName + "'");
		
		if (registerConfig.getCustomSubmissionConfig().get("checkIfExists") != null) {
			this.checkIfExists = registerConfig.getCustomSubmissionConfig().get("checkIfExists").getValues().get(0).equalsIgnoreCase("true");
		} else {
			this.checkIfExists = true;
		}

	}

	@Override
	public String createTremoloUser(NewUserRequest newUser, List<String> errors, AuthInfo userData)
			throws ProvisioningException {
		
		if (errors.size() == 0) {
		
			String targetName = newUser.getAttributes().get("cluster");
			
			if (targetName == null) {
				targetName = this.targetName;
			}
			
			OpenShiftTarget target = (OpenShiftTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(targetName).getProvider();
			
			HttpCon con = null;
			try {
				String token = target.getAuthToken();
				con = target.createClient();
				
				
				if (this.checkIfExists) {
					if (target.isObjectExistsByName(token, con, "/api/v1/namespaces", newUser.getAttributes().get(this.projectAttributeName))) {
						
						errors.add("Namespace name already exists");
						return "";
					} 
				}
				
			} catch (Exception e) {
				throw new ProvisioningException("Could not check if namespace exists",e);
			} finally {
				if (con != null) {
					try {
						con.getHttp().close();
					} catch (IOException e) {
						//doesn't matter
					}
					con.getBcm().close();
					
				}
			}
		
			if (target.getGitUrl() != null && ! target.getGitUrl().isEmpty()) {
				String gitUrlForNs = newUser.getAttributes().get("gitUrl");
				String sshPrivKey = newUser.getAttributes().get("gitSshKey");
				
				if (gitUrlForNs == null || gitUrlForNs.isEmpty()) {
					errors.add("Git URL is required for clusters configured to use git");
				}
				
				if (sshPrivKey == null || sshPrivKey.isEmpty()) {
					errors.add("Git SSH Private Key is required for clusters configured to use git");
				}
				
				if (errors.size() > 0) {
					return "";
				}
				
				GitUtils gitUtil = new GitUtils(gitUrlForNs,sshPrivKey);
				
				try {
					gitUtil.checkOut();
				} catch (Throwable t) {
					logger.warn("Could not checkout '" + gitUrlForNs + "'",t);
					errors.add(t.getMessage());
				} finally {
					gitUtil.cleanup();
				}
			}
		
			return this.workflowName;
		
		
		} else {
			return "";
		}
	}

	@Override
	public void setWorkflowParameters(Map<String, Object> wfParameters, NewUserRequest newUser, AuthInfo userData)
			throws ProvisioningException {
		String nameSpace = newUser.getAttributes().get("nameSpace");
		wfParameters.put("namespace", nameSpace);
		
		
		String targetName = newUser.getAttributes().get("cluster");
		
		if (targetName == null) {
			targetName = this.targetName;
		}
		wfParameters.put("cluster", targetName);
		
		wfParameters.put("fully-qualified-namespace", new StringBuilder().append(targetName).append(".").append(nameSpace).toString());
	}

}
