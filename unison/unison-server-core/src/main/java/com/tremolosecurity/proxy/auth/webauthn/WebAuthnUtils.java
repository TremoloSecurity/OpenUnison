/*******************************************************************************
 * Copyright (c) 2021 Tremolo Security, Inc.
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
package com.tremolosecurity.proxy.auth.webauthn;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import jakarta.servlet.ServletException;

import org.apache.commons.codec.binary.Base64;

import com.google.gson.Gson;
import com.tremolosecurity.provisioning.core.ProvisioningParams;
import com.tremolosecurity.provisioning.service.util.TremoloUser;
import com.tremolosecurity.provisioning.service.util.WFCall;
import com.tremolosecurity.provisioning.util.EncryptedMessage;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.webauthn4j.authenticator.Authenticator;

public class WebAuthnUtils {
	static Gson gson = new Gson();
	
	
	public static void storeWebAuthnUserData(WebAuthnUserData webAuthnUserData,String encryptionKeyName,AuthInfo userData,String workflowName,String uidAttributeName,String challengeStoreAttribute) throws Exception {
		storeWebAuthnUserData(webAuthnUserData,encryptionKeyName,userData,workflowName,uidAttributeName,challengeStoreAttribute,null,null);
		
	}
	
	public static void storeWebAuthnUserData(WebAuthnUserData webAuthnUserData,String encryptionKeyName,AuthInfo userData,String workflowName,String uidAttributeName,String challengeStoreAttribute,String credentialIdAttribute,OpenUnisonAuthenticator newAuthentictor) throws Exception {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(baos);
		oos.writeObject(webAuthnUserData);
		
		
		EncryptedMessage msg = new EncryptedMessage();
		
		SecretKey key = GlobalEntries.getGlobalEntries().getConfigManager().getSecretKey(encryptionKeyName);
		if (key == null) {
			throw new Exception("User data message encryption key not found");
		}
		
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		msg.setMsg(cipher.doFinal(baos.toByteArray()));
		msg.setIv(cipher.getIV());
		
		
		
		baos = new ByteArrayOutputStream();
		
		DeflaterOutputStream compressor  = new DeflaterOutputStream(baos,new Deflater(Deflater.BEST_COMPRESSION,true));
		
		Gson gson = new Gson();
		
		compressor.write(gson.toJson(msg).getBytes("UTF-8"));
		compressor.flush();
		compressor.close();
		
		
		
		String b64 = new String( java.util.Base64.getEncoder().encodeToString(baos.toByteArray()));
		
		userData.getAttribs().put(challengeStoreAttribute, new Attribute(challengeStoreAttribute,b64));
		
		
		WFCall wc = new WFCall();
		wc.setName(workflowName);
		wc.setUidAttributeName(uidAttributeName);
		TremoloUser tu = new TremoloUser();
		tu.setUid(userData.getAttribs().get(uidAttributeName).getValues().get(0));
		tu.getAttributes().add(new Attribute(uidAttributeName,userData.getAttribs().get(uidAttributeName).getValues().get(0)));
		tu.getAttributes().add(new Attribute(challengeStoreAttribute,b64));
		
		if (credentialIdAttribute != null && newAuthentictor != null) {
			String b64url = java.util.Base64.getUrlEncoder().encodeToString(newAuthentictor.getAttestedCredentialData().getCredentialId());
			while (b64url.charAt(b64url.length() - 1) == '=') {
				b64url = b64url.substring(0,b64url.length() - 1);
			}
			tu.getAttributes().add(new Attribute(credentialIdAttribute,b64url));
		}
		
		wc.setUser(tu);
		Map<String,Object> req = new HashMap<String,Object>();
		req.put(ProvisioningParams.UNISON_EXEC_TYPE, ProvisioningParams.UNISON_EXEC_SYNC);
		wc.setRequestParams(req);
		
		
		
		GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getWorkFlow(workflowName).executeWorkflow(wc);
	}
	
	public static WebAuthnUserData lookupWebAuthnUserData(AuthInfo userData, String attributeName, String encryptionKeyName) throws ServletException {
		Attribute encData = userData.getAttribs().get(attributeName);
		
		
		
		if (encData == null) {
			return null;
		} else {
			try {
				String encAuthData = encData.getValues().get(0);
				String encryptedAuth = inflate(encAuthData);
				
				SecretKey key = GlobalEntries.getGlobalEntries().getConfigManager().getSecretKey(encryptionKeyName);
				if (key == null) {
					throw new Exception("encryption key not found");
				}
				
				EncryptedMessage msg = gson.fromJson(encryptedAuth, EncryptedMessage.class);
				IvParameterSpec spec =  new IvParameterSpec(msg.getIv());
			    Cipher cipher;
			    
			    cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
				cipher.init(Cipher.DECRYPT_MODE, key,spec);
				
				
				byte[] bytes = cipher.doFinal(msg.getMsg());
				ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));
				WebAuthnUserData webAuthnData = (WebAuthnUserData) ois.readObject();
				return webAuthnData;
			} catch (Exception e) {
				throw new ServletException("Could not extract webauthn user data",e);
			}
			
		}
		
		
		
	}
	
	private static String inflate(String saml) throws Exception {
		byte[] compressedData = Base64.decodeBase64(saml);
		ByteArrayInputStream bin = new ByteArrayInputStream(compressedData);
		
		InflaterInputStream decompressor  = new InflaterInputStream(bin,new Inflater(true));
		//decompressor.setInput(compressedData);
		
		// Create an expandable byte array to hold the decompressed data
		ByteArrayOutputStream bos = new ByteArrayOutputStream(compressedData.length);
		
		// Decompress the data
		byte[] buf = new byte[1024];
		int len;
		while ((len = decompressor.read(buf)) > 0) {
		    
		        
		        bos.write(buf, 0, len);
		    
		}
		try {
		    bos.close();
		} catch (IOException e) {
		}

		// Get the decompressed data
		byte[] decompressedData = bos.toByteArray();
		
		String decoded = new String(decompressedData);
		
		return decoded;
	}
}
