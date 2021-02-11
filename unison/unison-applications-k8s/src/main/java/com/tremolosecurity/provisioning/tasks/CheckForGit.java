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
import java.io.UnsupportedEncodingException;
import java.util.Map;

import org.apache.log4j.Logger;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;

public class CheckForGit implements CustomTask {
	
	static Logger logger = Logger.getLogger(CheckForGit.class);

	String namespace;
	transient WorkflowTask task;
	
	boolean findNamespaceRepository;
	
	
	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
		if (params.get("namespace") != null) {
			this.namespace = params.get("namespace").getValues().get(0);
		} else {
			this.namespace = null;
		}
		
		if (params.get("findNamespaceRepository") != null) {
			this.findNamespaceRepository = params.get("findNamespaceRepository").getValues().get(0).equalsIgnoreCase("true");
		} else {
			this.findNamespaceRepository = true;
		}
		
		
		this.task = task;

	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
		this.task = task;

	}

	@Override
	public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {
		String localNamespace = null;
		
		if (this.namespace != null) {
			localNamespace = this.task.renderTemplate(namespace, request);
		}
		
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
			
			
			if (this.findNamespaceRepository) {
				findNamespaceGitUrl(user, request, localNamespace, target);
			}
		}
		
		return true;
	}

	private void findNamespaceGitUrl(User user, Map<String, Object> request, String localNamespace,
			OpenShiftTarget target) throws ProvisioningException {
		if (user.getAttribs().get("gitUrl") != null) {
			//this is an add, get urls from the user
			request.put("namespaceGitUrl", user.getAttribs().get("gitUrl").getValues().get(0));
			request.put("gitUrlAnnotation", "tremolo.io/giturl: " + user.getAttribs().get("gitUrl").getValues().get(0));
			
			try {
				String privateKey = user.getAttribs().get("gitSshKey").getValues().get(0).trim() + "\n";
				String b64Key = java.util.Base64.getEncoder().encodeToString(privateKey.getBytes("UTF-8"));
				request.put("b64sshkey", b64Key);
			} catch (UnsupportedEncodingException e) {
				throw new ProvisioningException("Could not generate base64 key",e);
			}
		} else {
			// this is not an add, get the git URL from the namespace
			String namespaceUri = "/api/v1/namespaces/" + localNamespace;
			HttpCon http = null;
			try {
				http = target.createClient();
				String json = target.callWS(target.getAuthToken(), http, namespaceUri);
				JSONObject root = (JSONObject) new JSONParser().parse(json);
				if (root.get("kind") != null && ! root.get("kind").equals("Namespace")) {
					logger.error("Not a namespace : '" + json + "'");
					throw new ProvisioningException("Could not lookup '" + localNamespace + "'");
				}
				
				JSONObject annotations = (JSONObject) ((JSONObject) root.get("metadata")).get("annotations");
				if (annotations == null) {
					logger.error("No annotations : '" + json + "'");
					throw new ProvisioningException("Could not lookup '" + localNamespace + "'");
				}
				
				String gitUrl = (String) annotations.get("tremolo.io/giturl");
				if (gitUrl == null) {
					logger.error("No tremolo.io/giturl annotation : '" + json + "'");
					throw new ProvisioningException("Could not lookup '" + localNamespace + "'");
				}
				
				request.put("namespaceGitUrl", gitUrl);
				
			} catch (Exception e) {
				throw new ProvisioningException("Could not retrieve namespace information",e);
			} finally {
				if (http != null) {
					try {
						http.getHttp().close();
					} catch (IOException e) {
						
					}
					http.getBcm().close();
				}
			}
			
		}
	}

}
