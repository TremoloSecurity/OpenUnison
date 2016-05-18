/*******************************************************************************
 * Copyright 2016 Tremolo Security, Inc.
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
package com.tremolosecurity.scalejs.token.password;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import com.google.gson.Gson;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.provisioning.util.EncryptedMessage;
import com.tremolosecurity.proxy.myvd.inserts.admin.PBKDF2;
import com.tremolosecurity.saml.Attribute;

public class SetRandomPassword implements CustomTask {

	
	transient ConfigManager cfgMgr;
	String encryptionKey;
	String attributeName;
	private SecureRandom random = new SecureRandom();
	
	
	public void init(WorkflowTask task, Map<String, Attribute> params)
			throws ProvisioningException {
		this.cfgMgr = task.getConfigManager();
		this.encryptionKey = params.get("keyName").getValues().get(0);
		this.attributeName = params.get("attributeName").getValues().get(0);
	}

	public void reInit(WorkflowTask task) throws ProvisioningException {
		this.cfgMgr = task.getConfigManager();

	}

	public boolean doTask(User user, Map<String, Object> request)
			throws ProvisioningException {
		String password = new BigInteger(130, random).toString(32);
		
		try {
			//remove {myvd}
			password = PBKDF2.generateHash(password).substring(7);
			
		} catch (InvalidKeyException | NoSuchAlgorithmException | UnsupportedEncodingException e) {
			throw new ProvisioningException("Could not generate password",e);
		}
		
		SecretKey key = this.cfgMgr.getSecretKey(this.encryptionKey);
		if (key == null) {
			throw new ProvisioningException("Encryption key not found");
		}
		
		EncryptedMessage msg = new EncryptedMessage();
		
		
		try {
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			msg.setMsg(cipher.doFinal(password.getBytes("UTF-8")));
			msg.setIv(cipher.getIV());
			Gson gson = new Gson();
			String json = gson.toJson(msg);
			user.setPassword(password);
			user.getAttribs().put(this.attributeName, new Attribute(this.attributeName,json));
		} catch (Throwable t) {
			throw new ProvisioningException("Could not generate random password",t);
		}
		
		
		return true;
	}
	
	
}
