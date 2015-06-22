/*
Copyright 2015 Tremolo Security, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/


package com.tremolosecurity.provisioning.customTasks;

import java.io.ByteArrayOutputStream;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.net.util.Base64;
import org.bouncycastle.util.encoders.Base64Encoder;

import com.google.gson.Gson;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.json.Token;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.proxy.auth.otp.TOTPKey;
import com.tremolosecurity.saml.Attribute;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;

public class CreateOTPKey implements CustomTask {
	//for key data
	//https://code.google.com/p/google-authenticator/wiki/KeyUriFormat
	
	
	
	String attributeName;
	String encryptionKey;
	String hostName;
	
	transient WorkflowTask task;
	
	public void init(WorkflowTask task, Map<String, Attribute> params)
			throws ProvisioningException {
		Attribute attr = params.get("attributeName");
		if (attr == null) {
			throw new ProvisioningException("attributeName not found");
		}
		
		this.attributeName = attr.getValues().get(0);
		
		attr = params.get("encryptionKey");
		if (attr == null) {
			throw new ProvisioningException("encryptionKey not found");
		}
		
		this.encryptionKey = attr.getValues().get(0);
		
		attr = params.get("hostName");
		if (attr == null) {
			throw new ProvisioningException("hostName not found");
		}
		
		this.hostName = attr.getValues().get(0);
		
		this.task = task;
	}

	public void reInit(WorkflowTask task) throws ProvisioningException {
		this.task = task;

	}

	public boolean doTask(User user, Map<String, Object> request)
			throws ProvisioningException {
		GoogleAuthenticator ga = new GoogleAuthenticator();
		GoogleAuthenticatorKey key = ga.createCredentials();
		String attrVal = null;
		
		attrVal = generateEncryptedToken(user.getUserID(), key,this.hostName,this.task.getConfigManager(),this.encryptionKey);
		
		Attribute keyattr = new Attribute(this.attributeName);
		keyattr.getValues().add(attrVal);
		user.getAttribs().put(this.attributeName, keyattr);
		return true;
	}

	public static String generateEncryptedToken(String userID, GoogleAuthenticatorKey key,
			String hostName,ConfigManager cfg,String encryptionKey) throws ProvisioningException {
		TOTPKey totpkey = new TOTPKey();
		totpkey.setHost(hostName);
		totpkey.setScratchCodes(key.getScratchCodes());
		totpkey.setSecretKey(key.getKey());
		totpkey.setUserName(userID);
		totpkey.setValidationCode(key.getVerificationCode());
		
		Gson gson = new Gson();
		String json = gson.toJson(totpkey);
		SecretKey sc = cfg.getSecretKey(encryptionKey);
		String attrVal = null;
		try {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			baos.write(json.getBytes("UTF-8"));
			
		    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE,sc );
			
			byte[] encJson = cipher.doFinal(baos.toByteArray());
			String base64d = new String(org.bouncycastle.util.encoders.Base64.encode(encJson));
			
			Token token = new Token();
			token.setEncryptedRequest(base64d);
			token.setIv(new String(org.bouncycastle.util.encoders.Base64.encode(cipher.getIV())));
			
			json = gson.toJson(token);
			attrVal = new String(org.bouncycastle.util.encoders.Base64.encode(json.getBytes("UTF-8")));
			
			
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not encrypt key",e);
		}
		return attrVal;
	}

}
