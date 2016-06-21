/*******************************************************************************
 * Copyright 2016 Tremolo Security, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package com.tremolosecurity.scalejs.token.totp;

import java.util.HashMap;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.servlet.http.HttpSession;

import org.apache.logging.log4j.Logger;
import org.apache.xml.security.utils.Base64;

import com.google.gson.Gson;
import com.tremolosecurity.json.Token;
import com.tremolosecurity.provisioning.util.EncryptedMessage;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.auth.otp.TOTPKey;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.scalejs.token.sdk.TokenLoader;
import com.tremolosecurity.server.GlobalEntries;

public class TOTPToken implements TokenLoader {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(TOTPToken.class.getName());
	
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
	public void init(HttpFilterConfig config,com.tremolosecurity.scalejs.token.cfg.ScaleTokenConfig scaleTokenConfig) throws Exception {
		this.encryptionKey = this.loadAttributeValue("encryptionKey", "Encryption Key", config);
		this.attributeName = this.loadAttributeValue("attributeName", "Attribute Name", config);
		scaleTokenConfig.setQrCodeAttribute("TOTP URL");
	}

	@Override
	public Object loadToken(AuthInfo user, HttpSession session) throws Exception {
		HashMap<String,String> tokenRet = new HashMap<String,String>();
		
		Attribute attr = user.getAttribs().get(this.attributeName);
		if (attr != null) {
			String json = attr.getValues().get(0);
			
			
			
			SecretKey decryptionKey = GlobalEntries.getGlobalEntries().getConfigManager().getSecretKey(encryptionKey);
			
			Gson gson = new Gson();
			Token token = gson.fromJson(new String(Base64.decode(json.getBytes("UTF-8"))), Token.class);
			byte[] iv = org.bouncycastle.util.encoders.Base64.decode(token.getIv());
			IvParameterSpec spec =  new IvParameterSpec(iv);
		    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, decryptionKey,spec);
			
			String decryptedJSON = new String(cipher.doFinal(Base64.decode(token.getEncryptedRequest().getBytes("UTF-8"))));
			
			if (logger.isDebugEnabled()) logger.debug(decryptedJSON);
			
			TOTPKey totp = gson.fromJson(decryptedJSON, TOTPKey.class);
			tokenRet.put("TOTP URL", "otpauth://totp/" + totp.getUserName() + "@" + totp.getHost() + "?secret=" + totp.getSecretKey());
			
			
			
			
			
			
			
			
			
			
			
			

			
		} else {
			tokenRet.put("TOTP URL", "No password found");
		}
		
		return tokenRet;
	}

}
