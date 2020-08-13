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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;

import org.apache.commons.codec.binary.Base64;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.io.pem.PemWriter;

import org.gitlab4j.api.GitLabApi;
import org.gitlab4j.api.GitLabApiClient;
import org.gitlab4j.api.GitLabApiException;
import org.gitlab4j.api.models.Project;
import org.gitlab4j.api.models.ProjectHook;
import org.gitlab4j.api.models.Visibility;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.provisioning.util.GenPasswd;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.gitlab.provisioning.targets.GitlabUserProvider;

public class CreateProject implements CustomTask {
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(CreateProject.class.getName());
	
	String namespace;
	String name;
	String description;
	boolean issuesEnabled;
	boolean mergeRequestsEnabled;
	boolean wikiEnabled;
	boolean snipitsEnabled;
	int visibility;

	String targetName;

	transient WorkflowTask task;
	
	String gitSshHost;
	
	boolean createWebHook;
	String webhookDomainSuffix;
	String webhookSecretRequestName;

	private String webhookBranchFilter;

	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
		this.namespace = params.get("namespace").getValues().get(0);
		this.name = params.get("name").getValues().get(0);
		this.description = params.get("description").getValues().get(0);
		this.issuesEnabled = params.get("issuesEnabled").getValues().get(0).equalsIgnoreCase("true");
		this.mergeRequestsEnabled = params.get("mergeRequestsEnabled").getValues().get(0).equalsIgnoreCase("true");
		this.wikiEnabled = params.get("wikiEnabled").getValues().get(0).equalsIgnoreCase("true");
		this.snipitsEnabled = params.get("snipitsEnabled").getValues().get(0).equalsIgnoreCase("true");
		this.visibility = Integer.parseInt(params.get("visibility").getValues().get(0));
		this.targetName = params.get("targetName").getValues().get(0);
		this.gitSshHost = params.get("gitSshHost").getValues().get(0);
		
		this.createWebHook = params.get("createWebhook") != null && params.get("createWebhook").getValues().get(0).equalsIgnoreCase("true");
		if (this.createWebHook) {
			this.webhookDomainSuffix = params.get("webhookSuffix").getValues().get(0);
			this.webhookBranchFilter = params.get("webhookBranchFilter").getValues().get(0);
			this.webhookSecretRequestName = params.get("webhookSecretRequestName").getValues().get(0);
		}
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

		GitlabUserProvider gitlab = (GitlabUserProvider) GlobalEntries.getGlobalEntries().getConfigManager()
				.getProvisioningEngine().getTarget(this.targetName).getProvider();
		GitLabApi api = gitlab.getApi();

		String localNamespace = task.renderTemplate(this.namespace, request);
		String localName = task.renderTemplate(this.name, request);
		String localDescription = task.renderTemplate(this.description, request);
		
		
		
		try {
			try {
				Project existingProject = api.getProjectApi().getProject(localNamespace, localName);
				if (existingProject != null) {
					logger.warn("Project " + localNamespace + "/" + localName + " already exists, skipping");
					return true;
				}
			} catch (GitLabApiException e) {
				if (e.getHttpStatus() != 404) {
					throw new ProvisioningException("Error looking up project " + localNamespace + "/" + localName,e);
				}
			}
			
			Project projectSpec = new Project()
					.withNamespace(api.getNamespaceApi().findNamespaces(localNamespace).get(0)).withName(localName)
					.withDescription(localDescription).withIssuesEnabled(this.issuesEnabled)
					.withMergeRequestsEnabled(this.mergeRequestsEnabled).withWikiEnabled(this.wikiEnabled)
					.withSnippetsEnabled(this.snipitsEnabled).withVisibilityLevel(this.visibility);

			Project newProject = api.getProjectApi().createProject(projectSpec);

			GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().logAction(gitlab.getName(),
					false, ActionType.Add, approvalID, workflow,
					"gitlab-project-" + newProject.getNameWithNamespace() + "-name", newProject.getNameWithNamespace());

			// generate deployment key
			KeyPairGenerator generator;
			generator = KeyPairGenerator.getInstance("RSA");
			// or: generator = KeyPairGenerator.getInstance("DSA");
			generator.initialize(2048);
			KeyPair keyPair = generator.genKeyPair();
			String sshPubKey = "ssh-rsa "
					+ Base64.encodeBase64String(encodePublicKey((RSAPublicKey) keyPair.getPublic()))
					+ " openunison-deploy-key";

			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			org.bouncycastle.openssl.PEMWriter genPrivKey = new org.bouncycastle.openssl.PEMWriter(
					new OutputStreamWriter(baos));
			genPrivKey.writeObject(keyPair.getPrivate());
			genPrivKey.close();

			String pem = new String(baos.toByteArray());

			api.getDeployKeysApi().addDeployKey(newProject, "openunison-deploy-key", sshPubKey, false);

			GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().logAction(gitlab.getName(),
					false, ActionType.Add, approvalID, workflow,
					"gitlab-project-" + newProject.getNameWithNamespace() + "-deploykey", "openunison-deploy-key");

			
			
			try {
	            String base64PrivKey = java.util.Base64.getEncoder().encodeToString(pem.getBytes("UTF-8"));
	            request.put("base64SshPrivateKey", base64PrivKey);
	        } catch (UnsupportedEncodingException e) {
	            throw new ProvisioningException("Could get key",e);
	        }
			
			
			
			String gitUrl = newProject.getSshUrlToRepo();
	        String prefix = gitUrl.substring(0,gitUrl.indexOf("@") + 1);
	        String suffix = gitUrl.substring(gitUrl.indexOf(":"));
	        String newGitUrl = new StringBuilder().append(prefix).append(this.gitSshHost).append(suffix).toString();

	        request.put("gitSshInternalURL",newGitUrl);

			
			
			
			
			
			request.put("gitSshUrl", newProject.getSshUrlToRepo());
			request.put("gitPrivateKey", pem);
			request.put("newProjectJSON", newProject.toString());
			
			
			
			if (createWebHook) {
				String webhookToken = new GenPasswd(50).getPassword();
				String b64WebhookToken = java.util.Base64.getEncoder().encodeToString(webhookToken.getBytes("UTF-8"));
				
				request.put(webhookSecretRequestName,webhookToken);
				request.put("b64" + webhookSecretRequestName,b64WebhookToken);
				
				String webhookUrl = new StringBuilder().append("https://").append(localName).append(".").append(this.webhookDomainSuffix).toString();
				ProjectHook hook = new ProjectHook().withPushEvents(true).withPushEventsBranchFilter(this.webhookBranchFilter);
				api.getProjectApi().addHook(newProject, webhookUrl, hook, false, webhookToken);
				
				GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().logAction(gitlab.getName(),false, ActionType.Add, approvalID, workflow, "gitlab-project-" + newProject.getNameWithNamespace() + "-webhook", this.webhookBranchFilter);
			}
			
			
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not create project", e);
		}
		return true;
	}

	byte[] encodePublicKey(RSAPublicKey key) throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		/* encode the "ssh-rsa" string */
		byte[] sshrsa = new byte[] { 0, 0, 0, 7, 's', 's', 'h', '-', 'r', 's', 'a' };
		out.write(sshrsa);
		/* Encode the public exponent */
		BigInteger e = key.getPublicExponent();
		byte[] data = e.toByteArray();
		encodeUInt32(data.length, out);
		out.write(data);
		/* Encode the modulus */
		BigInteger m = key.getModulus();
		data = m.toByteArray();
		encodeUInt32(data.length, out);
		out.write(data);
		return out.toByteArray();
	}

	void encodeUInt32(int value, OutputStream out) throws IOException {
		byte[] tmp = new byte[4];
		tmp[0] = (byte) ((value >>> 24) & 0xff);
		tmp[1] = (byte) ((value >>> 16) & 0xff);
		tmp[2] = (byte) ((value >>> 8) & 0xff);
		tmp[3] = (byte) (value & 0xff);
		out.write(tmp);
	}

}
