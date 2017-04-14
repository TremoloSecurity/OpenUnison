/*******************************************************************************
 * Copyright 2017 Tremolo Security, Inc.
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
package com.tremolosecurity.unison.u2f.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Type;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.binary.Base64;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.google.u2f.server.data.SecurityKeyData;
import com.tremolosecurity.provisioning.util.EncryptedMessage;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.google.u2f.KeyHolder;




public class U2fUtil {
	static Gson gson = new Gson();
	
	
	
	public static String encode(List<SecurityKeyData> devices,String encyrptionKeyName) throws Exception {
		ArrayList<KeyHolder> keys = new ArrayList<KeyHolder>();
		for (SecurityKeyData dr : devices) {
			KeyHolder kh = new KeyHolder();
			kh.setCounter(dr.getCounter());
			kh.setEnrollmentTime(dr.getEnrollmentTime());
			kh.setKeyHandle(dr.getKeyHandle());
			kh.setPublicKey(dr.getPublicKey());
			kh.setTransports(dr.getTransports());
			keys.add(kh);
		}
		
		String json = gson.toJson(keys);
		EncryptedMessage msg = new EncryptedMessage();
		
		SecretKey key = GlobalEntries.getGlobalEntries().getConfigManager().getSecretKey(encyrptionKeyName);
		if (key == null) {
			throw new Exception("Queue message encryption key not found");
		}
		
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		msg.setMsg(cipher.doFinal(json.getBytes("UTF-8")));
		msg.setIv(cipher.getIV());
		
		
		
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		
		DeflaterOutputStream compressor  = new DeflaterOutputStream(baos,new Deflater(Deflater.BEST_COMPRESSION,true));
		
		compressor.write(gson.toJson(msg).getBytes("UTF-8"));
		compressor.flush();
		compressor.close();
		
		
		
		String b64 = new String( Base64.encodeBase64(baos.toByteArray()));
		
		return b64;
		
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
	
	
	
	public static List<SecurityKeyData> loadUserKeys(AuthInfo userData,String challengeStoreAttribute,String encyrptionKeyName)
			throws Exception, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Attribute challengeAttr = userData.getAttribs().get(challengeStoreAttribute);
		Type t = new TypeToken<List<KeyHolder>>(){}.getType();
		ArrayList<SecurityKeyData> devices = new ArrayList<SecurityKeyData>();
		
		if (challengeAttr != null) {
			SecretKey key = GlobalEntries.getGlobalEntries().getConfigManager().getSecretKey(encyrptionKeyName);
			if (key == null) {
				throw new Exception("Queue message encryption key not found");
			}
			
			
			
			
			EncryptedMessage msg = gson.fromJson(inflate(challengeAttr.getValues().get(0)), EncryptedMessage.class);
			IvParameterSpec spec =  new IvParameterSpec(msg.getIv());
		    Cipher cipher;
		    
		    cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, key,spec);
			
			
			byte[] bytes = cipher.doFinal(msg.getMsg());
			String json = new String(bytes);
			java.util.List<KeyHolder> fromJSON = gson.fromJson(json, t);
			for (KeyHolder kh : fromJSON) {
				devices.add(new SecurityKeyData(kh.getEnrollmentTime(),kh.getKeyHandle(),kh.getPublicKey(),null,kh.getCounter()));
			}
			
		}
		return devices;
	}
	
	public static String getApplicationId(HttpServletRequest request) throws MalformedURLException {
		StringBuffer appID = new StringBuffer();
		URL url = new URL(request.getRequestURL().toString());
		appID.append(url.getProtocol()).append("://").append(url.getHost());
		
		if (! (url.getProtocol().equalsIgnoreCase("http") && (url.getPort() == 80 || url.getPort() <= 0)) || ! (  url.getProtocol().equalsIgnoreCase("https") && (url.getPort() == 443 || url.getPort() <= 0)) ) {
			appID.append(':').append(url.getPort());
		}
		

		
		return appID.toString();
		
	}
}
