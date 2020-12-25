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

import java.io.UnsupportedEncodingException;
import java.util.Map;

import org.apache.log4j.Logger;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;

public class CheckForGit implements CustomTask {
	
	static Logger logger = Logger.getLogger(CheckForGit.class);

	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {


	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {


	}

	@Override
	public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {
		
		String targetName = (String) request.get("cluster");
		
		logger.info("Target : '" + targetName + "'");
	
		OpenShiftTarget target = (OpenShiftTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(targetName).getProvider();
		
		if (target == null) {
			throw new ProvisioningException("Target '" + targetName + "' not found");
		}
		
		if (target.getGitUrl() == null || target.getGitUrl().isEmpty()) {
			logger.info("Target '" + targetName + "' does not support git");
			user.getAttribs().put("useGit", new Attribute("useGit","false"));
			request.put("useGit", "false");
		} else {
			logger.info("Target '" + targetName + "' does supports git");
			user.getAttribs().put("useGit", new Attribute("useGit","true"));
			request.put("useGit", "true");
			request.put("clusterGitUrl", target.getGitUrl());
			request.put("namespaceGitUrl", user.getAttribs().get("gitUrl").getValues().get(0));
			
			request.put("gitUrlAnnotation", "tremolo.io/giturl: " + user.getAttribs().get("gitUrl").getValues().get(0));
			
			try {
				String privateKey = user.getAttribs().get("gitSshKey").getValues().get(0).trim() + "\n";
				String b64Key = java.util.Base64.getEncoder().encodeToString(privateKey.getBytes("UTF-8"));
				request.put("b64sshkey", b64Key);
			} catch (UnsupportedEncodingException e) {
				throw new ProvisioningException("Could not generate base64 key",e);
			}
		}
		
		return true;
	}

}
