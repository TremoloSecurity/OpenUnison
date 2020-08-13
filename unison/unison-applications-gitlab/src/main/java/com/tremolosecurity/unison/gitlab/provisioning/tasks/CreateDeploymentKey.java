package com.tremolosecurity.unison.gitlab.provisioning.tasks;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.gitlab4j.api.GitLabApi;
import org.gitlab4j.api.GitLabApiException;
import org.gitlab4j.api.models.Project;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.gitlab.provisioning.targets.GitlabUserProvider;

public class CreateDeploymentKey implements CustomTask {
	
	String targetName;
	String namespace;
	String project;
	String privateKeyRequestName;
	String privateKeyRequestNamePT;
	
	String keyLabel;
	boolean makeWriteable;
	
	
	transient WorkflowTask task;

	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
		this.task = task;
		
		this.targetName = params.get("targetName").getValues().get(0);
		this.namespace = params.get("namespace").getValues().get(0);
		this.project = params.get("project").getValues().get(0);
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

		GitlabUserProvider gitlab = (GitlabUserProvider) GlobalEntries.getGlobalEntries().getConfigManager()
				.getProvisioningEngine().getTarget(this.targetName).getProvider();
		GitLabApi api = gitlab.getApi();
		
		String localNamespace = task.renderTemplate(this.namespace, request);
		String localProjectName = task.renderTemplate(this.project, request);
		String localLabel = task.renderTemplate(this.keyLabel, request);
		
		try {
			Project project = api.getProjectApi().getProject(localNamespace, localProjectName);
		
			// generate deployment key
			KeyPairGenerator generator;
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
	
			api.getDeployKeysApi().addDeployKey(project, localLabel, sshPubKey, this.makeWriteable);
	
			GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().logAction(gitlab.getName(),
					false, ActionType.Add, approvalID, workflow,
					"gitlab-project-" + project.getNameWithNamespace() + "-deploykey", localLabel);
	
			
			
			try {
	            String base64PrivKey = java.util.Base64.getEncoder().encodeToString(pem.getBytes("UTF-8"));
	            request.put(privateKeyRequestName, base64PrivKey);
	            request.put(this.privateKeyRequestNamePT,pem);
	        } catch (UnsupportedEncodingException e) {
	            throw new ProvisioningException("Could get key",e);
	        }
		} catch (GitLabApiException | NoSuchAlgorithmException | IOException e) {
			throw new ProvisioningException("Error creating key for " + localNamespace + "/" + localProjectName,e);
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
