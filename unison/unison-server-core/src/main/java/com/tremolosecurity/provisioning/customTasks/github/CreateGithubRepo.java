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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpClient.Version;
import java.net.http.HttpResponse.BodyHandlers;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.jose4j.lang.JoseException;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.kohsuke.github.GHCreateRepositoryBuilder;
import org.kohsuke.github.GHDeployKey;
import org.kohsuke.github.GHEvent;
import org.kohsuke.github.GHHook;
import org.kohsuke.github.GHOrganization;
import org.kohsuke.github.GHRepository;
import org.kohsuke.github.GHRepository.Visibility;
import org.kohsuke.github.GHTeam;
import org.kohsuke.github.GitHub;
import org.kohsuke.github.GitHubBuilder;

import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.utils.Key;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.ProvisioningTarget;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.provisioning.core.providers.GitHubProvider;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.provisioning.util.GenPasswd;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;

public class CreateGithubRepo implements CustomTask {
	
	String targetName;
	String name;
	transient WorkflowTask task;
	
	String allowSquashMerge;
	String allowMergeCommit;
	String allowRebaseMerge;
	String deleteBranchOnMerge;
	String defaultBranch;
	String description;
	String homePage;
	String visibility;
	String issues;
	String projects;
	String wiki;
	String downloads;
	String isTemplate;
	String gitignoreTemplate;
	String licenseTemplate;
	String autoInit;
	String team;
	String owner;
	String deployKeyName;
	
	String webhookUrl;
	

	
	
	List<String> webhookEvents;

	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
		allowSquashMerge = loadOption("allowSquashMerge",params,"true");
		allowMergeCommit = loadOption("allowMergeCommit",params,"true");
		allowRebaseMerge = loadOption("allowRebaseMerge",params,"true");
		deleteBranchOnMerge = loadOption("deleteBranchOnMerge",params,"false");
		defaultBranch = loadOption("defaultBranch",params,"main");
		description = loadOption("description",params,null);
		homePage = loadOption("homePage",params,"");
		visibility = loadOption("visibility",params,"public");
		issues = loadOption("issues",params,"true");
		projects = loadOption("projects",params,"true");
		wiki = loadOption("wiki",params,"true");
		downloads = loadOption("downloads",params,"true");
		isTemplate = loadOption("isTemplate",params,"false");
		gitignoreTemplate = loadOption("gitignoreTemplate",params,"");
		licenseTemplate = loadOption("licenseTemplate",params,"");
		autoInit = loadOption("autoInit",params,"true");
		team = loadOption("team",params,"");
		owner = loadOption("owner",params,"");
		
		targetName = loadOption("targetName",params,null);
		name = loadOption("name",params,null);
		
		deployKeyName = loadOption("deployKeyName",params,"deployment-key");
		webhookUrl = loadOption("webhookUrl",params,"");
		
		
		if (webhookUrl != null && ! webhookUrl.isBlank()) {
			this.webhookEvents = new ArrayList<String>();
			Attribute webhookEvents = params.get("webhookEvents");
			if (webhookEvents != null) {
				this.webhookEvents.addAll(webhookEvents.getValues());
			} else {
				this.webhookEvents.add("*");
			}
		}
		

		this.task = task;
	}
	
	private String loadOption(String name,Map<String, Attribute> params,String defaultValue) throws ProvisioningException {
		Attribute val = params.get(name);
		if (val == null) {
			if (defaultValue == null) {
				throw new ProvisioningException(String.format("%s required",name));
			} else {
				return defaultValue;
			}
			
		} else {
			return val.getValues().get(0);
		}
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
		
		String lName = task.renderTemplate(name, request);
		
		GHRepository repo = null;
		
		try {
			repo = ghOrg.getRepository(lName);
		} catch (IOException e1) {
			throw new ProvisioningException(String.format("Could not create repository %s", lName),e1);
		}
		
		if (repo == null) {
			
				GHCreateRepositoryBuilder builder = ghOrg.createRepository(lName);

				try {
					builder

							.description(task.renderTemplate(description, request))

							// due to bug in library https://github.com/hub4j/github-api/issues/1456
							.private_(task.renderTemplate(visibility, request).equalsIgnoreCase("private"))
							// .visibility(Visibility.from(task.renderTemplate(visibility, request)));

							.allowMergeCommit(task.renderTemplate(allowMergeCommit, request).equalsIgnoreCase("true"))
							.allowRebaseMerge(task.renderTemplate(allowRebaseMerge, request).equalsIgnoreCase("true"))
							.allowSquashMerge(task.renderTemplate(allowSquashMerge, request).equalsIgnoreCase("true"))
							.autoInit(task.renderTemplate(autoInit, request).equalsIgnoreCase("true"))
							.defaultBranch(task.renderTemplate(defaultBranch, request))
							.deleteBranchOnMerge(
									task.renderTemplate(deleteBranchOnMerge, request).equalsIgnoreCase("true"))
							.gitignoreTemplate(task.renderTemplate(gitignoreTemplate, request))
							.downloads(task.renderTemplate(downloads, request).equalsIgnoreCase("true"))
							.issues(task.renderTemplate(issues, request).equalsIgnoreCase("true"))
							.isTemplate(task.renderTemplate(isTemplate, request).equalsIgnoreCase("true"))
							.projects(task.renderTemplate(projects, request).equalsIgnoreCase("true"))
							.homepage(task.renderTemplate(homePage, request));

					String llicenseTemplate = task.renderTemplate(licenseTemplate, request);
					if (!llicenseTemplate.isBlank()) {
						builder.licenseTemplate(llicenseTemplate);
					}

					String lowner = task.renderTemplate(owner, request);
					if (!lowner.isBlank()) {
						builder.owner(lowner);
					}

					String lteam = task.renderTemplate(team, request);
					if (!lteam.isBlank()) {
						GHTeam ghteam = ghOrg.getTeamByName(lteam);
						builder.team(ghteam);
					}

					repo = builder.create();

					GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().logAction(lTargetName,
							false, ActionType.Add, approvalID, workflow,
							String.format("github-repo-%s.%s-name", github.getOrgName(), repo.getName()),
							String.format("%s.%s", github.getOrgName(), repo.getName()));

				} catch (IOException e) {
					throw new ProvisioningException(String.format("Could not create repository %s", lName), e);
				}
			}
		
		
		
		request.put("gitSshUrl", repo.getSshUrl());
		
		try {
			
			String lDeployKeyName = this.task.renderTemplate(this.deployKeyName, request);
			
			boolean found = false;
			List<GHDeployKey> deployKeys = repo.getDeployKeys();
			
			for (GHDeployKey key : deployKeys) {
				if (key.getTitle().equals(lDeployKeyName)) {
					found = true;
					break;
				}
			}
			
			if (! found) {
			
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
				
				request.put("gitPrivateKey", pem);
				
				repo.addDeployKey(task.renderTemplate(this.deployKeyName, request), sshPubKey);
				
				
				GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().logAction(lTargetName,
						false, ActionType.Add, approvalID, workflow,
						String.format("github-repo-%s.%s-deploykey",github.getOrgName(),repo.getName()), task.renderTemplate(this.deployKeyName, request));
	
				
				
				try {
		            String base64PrivKey = java.util.Base64.getEncoder().encodeToString(pem.getBytes("UTF-8"));
		            request.put("base64SshPrivateKey", base64PrivKey);
		        } catch (UnsupportedEncodingException e) {
		            throw new ProvisioningException("Could get key",e);
		        }
				
				String keyName = String.format("%s-key-created", lName);
				
				user.getAttribs().put(keyName, new Attribute(keyName,"true"));
			}
			
			if (! this.webhookUrl.isBlank()) {
				String lWebHookUrl = task.renderTemplate(webhookUrl, request);
				URL webhookUrlObj = new URL(lWebHookUrl);
				found = false;
				List<GHHook> hooks = repo.getHooks();
				for (GHHook hook : hooks) {
					if (hook.getConfig().get("url").equals(lWebHookUrl)) {
						found = true;
						break;
					}
				}
				
				if (! found) {
					String webhookToken = new GenPasswd(50).getPassword();
					String b64WebhookToken = java.util.Base64.getEncoder().encodeToString(webhookToken.getBytes("UTF-8"));
					String webhookSecretRequestName = "github.webhook.secret." + lTargetName + "." + lName;
					request.put(webhookSecretRequestName,webhookToken);
					request.put("b64" + webhookSecretRequestName,b64WebhookToken);
					user.getAttribs().put(webhookSecretRequestName, new Attribute("webhookSecretRequestName","true"));
					
					HashMap<String,String> hookCfg = new HashMap<String,String>();
					
					hookCfg.put("url", lWebHookUrl);
					hookCfg.put("content_type", "json");
					hookCfg.put("secret", webhookToken);
					
					List<GHEvent> events = new ArrayList<GHEvent>(); 
					
					for (String event : this.webhookEvents) {
						String eventStr = task.renderTemplate(event, request);
						
						if (eventStr.equals("*")) {
							eventStr = "ALL";
						}
						
						GHEvent eventObj = GHEvent.valueOf(eventStr); 
						events.add(eventObj);
					}
					
					GHHook hook = repo.createHook("web", hookCfg, events, true);
					
					GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().logAction(lTargetName,
							false, ActionType.Add, approvalID, workflow,
							String.format("github-repo-%s.%s-webhook",github.getOrgName(),repo.getName()), lWebHookUrl);
				}
			}
			
			
		} catch (IOException | NoSuchAlgorithmException e) {
			throw new ProvisioningException(String.format("Could not add deployment key to %s", lName),e);
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
