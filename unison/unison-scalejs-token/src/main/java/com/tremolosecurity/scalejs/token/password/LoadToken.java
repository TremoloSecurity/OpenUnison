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

import java.util.HashMap;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.servlet.http.HttpSession;

import org.apache.logging.log4j.Logger;

import com.google.gson.Gson;
import com.tremolosecurity.provisioning.util.EncryptedMessage;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.scalejs.token.sdk.TokenLoader;
import com.tremolosecurity.server.GlobalEntries;

public class LoadToken implements TokenLoader {

	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(LoadToken.class.getName());
	
	String encryptionKey;
	String attributeName;
	
	
	private String loadAttributeValue(String name,String label,HttpFilterConfig config) throws Exception {
		Attribute attr = config.getAttribute(name);
		if (attr == null) {
			throw new Exception(label + " not found");
		}
		
		String val = attr.getValues().get(0);
		logger.info(label + ": '" + val + "'");
		
		return val;
	}
	
	@Override
	public void init(HttpFilterConfig config) throws Exception {
		this.encryptionKey = this.loadAttributeValue("encryptionKey", "Encryption Key", config);
		this.attributeName = this.loadAttributeValue("attributeName", "Attribute Name", config);

	}

	@Override
	public Object loadToken(AuthInfo user, HttpSession session) throws Exception {
		HashMap<String,String> token = new HashMap<String,String>();
		
		Attribute attr = user.getAttribs().get(this.attributeName);
		if (attr != null) {
			String json = attr.getValues().get(0);
			
			Gson gson = new Gson();
			EncryptedMessage em = gson.fromJson(json, EncryptedMessage.class);
			SecretKey key = GlobalEntries.getGlobalEntries().getConfigManager().getSecretKey(this.encryptionKey);
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			IvParameterSpec spec =  new IvParameterSpec(em.getIv());
			cipher.init(Cipher.DECRYPT_MODE, key,spec);
			
			byte[] bytes = cipher.doFinal(em.getMsg());
			String password = new String(bytes);
			token.put("Temporary Password", password);
		} else {
			token.put("Temporary Password", "No password found");
		}
		
		return token;
	}

}
