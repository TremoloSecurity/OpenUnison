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
import org.gitlab4j.api.GitLabApi;
import org.jose4j.lang.JoseException;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
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
import com.tremolosecurity.unison.gitlab.provisioning.targets.GitlabUserProvider;

public class CreateDeploymentKey implements CustomTask {
	
	static Logger logger = Logger.getLogger(CreateDeploymentKey.class.getName());
	
	String targetName;
	String repo;
	String privateKeyRequestName;
	String privateKeyRequestNamePT;
	
	String keyLabel;
	boolean makeWriteable;
	
	
	transient WorkflowTask task;

	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
		this.task = task;
		
		this.targetName = params.get("targetName").getValues().get(0);
		this.repo = params.get("repo").getValues().get(0);
		
		this.keyLabel = params.get("keyLabel").getValues().get(0);
		this.makeWriteable = params.get("makeWriteable").getValues().get(0).equalsIgnoreCase("true");
		this.privateKeyRequestName = params.get("privateKeyReuestName").getValues().get(0);
		this.privateKeyRequestNamePT = params.get("privateKeyReuestNamePT").getValues().get(0);

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
					break;
				}
			}
		} catch (IOException e1) {
			throw new ProvisioningException(String.format("Could not load keys %s in %s/%s", localLabel,github.getOrgName(),localRepo));
		}
		
		
		
		if (! found) {
			
			// generate deployment key
			KeyPairGenerator generator;
			try {
				generator = KeyPairGenerator.getInstance("RSA");
				// or: generator = KeyPairGenerator.getInstance("DSA");
				generator.initialize(2048);
				KeyPair keyPair = generator.genKeyPair();
				String sshPubKey = "ssh-rsa "
						+ Base64.encodeBase64String(encodePublicKey((RSAPublicKey) keyPair.getPublic()))
						+ " " + localLabel;
		
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				org.bouncycastle.openssl.PEMWriter genPrivKey = new org.bouncycastle.openssl.PEMWriter(
						new OutputStreamWriter(baos));
				genPrivKey.writeObject(keyPair.getPrivate());
				genPrivKey.close();
				String pem = new String(baos.toByteArray());
				
				createWriteableKey(github.getOrgName(),localRepo,github,localLabel,sshPubKey,lTargetName,approvalID,workflow,this.makeWriteable);
				
				try {
		            String base64PrivKey = java.util.Base64.getEncoder().encodeToString(pem.getBytes("UTF-8"));
		            request.put(privateKeyRequestName, base64PrivKey);
		            request.put(this.privateKeyRequestNamePT,pem);
		        } catch (UnsupportedEncodingException e) {
		            throw new ProvisioningException("Could get key",e);
		        }
				
			} catch (NoSuchAlgorithmException | IOException e) {
				throw new ProvisioningException(String.format("Could not create deployment key %s in %s/%s", localLabel,github.getOrgName(),localRepo));
			}
			

		
		
		} else {
			logger.warn(String.format("deployment key %s in %s/%s already exists", localLabel,github.getOrgName(),localRepo));
		}
		
		
		return true;
	}
	
	
	private void createWriteableKey(String org,String repo,GitHubProvider github,String title, String pemKey,String targetName,int approvalID,Workflow workflow, boolean makeWriteable2) throws ProvisioningException {
		
		JSONObject key = new JSONObject();
		key.put("title", title);
		key.put("key",pemKey);
		key.put("read_only", !makeWriteable2);
		
		
		HttpRequest request;
		try {
			request = HttpRequest.newBuilder()
					  .uri(new URI(String.format("%s/repos/%s/%s/keys", github.getApiHost(),github.getOrgName(),repo)))
					  .header("Authorization", String.format("Bearer %s", github.getToken()))
					  .POST(HttpRequest.BodyPublishers.ofString(key.toString()))
					  .build();
			HttpClient client = HttpClient.newBuilder()
			        .version(Version.HTTP_1_1).build();
			HttpResponse<String> response = client.send(request, BodyHandlers.ofString());
			
			if (response.statusCode() != 201) {
				throw new ProvisioningException(String.format("Could not create writeable key in %s/%s: %d / %s",org,repo,response.statusCode(),response.body()));
			}
			
			GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().logAction(targetName,
					false, ActionType.Add, approvalID, workflow,
					String.format("github-repo-%s.%s-deploykey",github.getOrgName(),repo), title);
			
			
		} catch (URISyntaxException | JoseException | IOException | ProvisioningException | ParseException | InterruptedException e) {
			throw new ProvisioningException(String.format("Could not create key %s/%s",org,repo),e);
		}
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
