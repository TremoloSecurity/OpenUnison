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


package com.tremolosecurity.lastmile;


import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.SecureRandom;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;


import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

import com.google.gson.Gson;
import com.tremolosecurity.json.Request;
import com.tremolosecurity.json.Token;
import com.tremolosecurity.saml.Attribute;

public class LastMile {
	public Request getRequest() {
		return request;
	}

	public Token getToken() {
		return token;
	}

	Request request;
	Token token;
	
	String altURI;
	
	SecureRandom sr;
	
	public LastMile() {
		this.sr = new SecureRandom();
		this.altURI = "";
	}
	
	public LastMile(String uri,DateTime notBefore,DateTime notAfter,int loginLevel,String authChain) throws URISyntaxException {
		this();
		
		this.request = new Request();
		this.token = new Token();
		
		this.request.setId(Long.toString(sr.nextLong()));
		this.request.setUri(URLDecoder.decode(uri));
		this.request.setLoginLevel(loginLevel);
		this.request.setAuthChain(authChain);
		
		this.request.setNotBefore(notBefore.withZone(DateTimeZone.UTC).toString());
		this.request.setNotAfter(notAfter.withZone(DateTimeZone.UTC).toString());
	}
	
	public List<Attribute> getAttributes() {
		return this.request.getAttrs();
	}
	
	public int getLoginLevel() {
		return this.request.getLoginLevel();
	}
	
	public String getAuthChain() {
		return this.request.getAuthChain();
	}
	
	public boolean isValid() {
		DateTime lnotBefore = new DateTime(this.request.getNotBefore());
		DateTime lnotAfter = new DateTime(this.request.getNotAfter());
		
		return lnotBefore.isBeforeNow() && lnotAfter.isAfterNow();
	}
	
	public boolean isValid(String uri) throws URISyntaxException {
		
		//URI nuri = new URI(uri);
		//uri = nuri.toASCIIString();
		uri = URLDecoder.decode(uri);
		
		/*//System.out.println("URI:'" + uri + "'");
		//System.out.println("this.request.getUri():'" + this.request.getUri() + "'");
		//System.out.println("this.altURI:'" + this.altURI + "'");
		//System.out.println("isValid:'" + isValid() + "'");*/
		
		return isValid() && (uri.equals(this.request.getUri()) || uri.equals(this.altURI));
	}
	
	public String generateLastMileToken(SecretKey encKey) throws Exception {
		Gson gson = new Gson();
		String json = gson.toJson(this.request);
		
		
		
		byte[] bjson = json.getBytes("UTF-8");
		
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, encKey);
		
		byte[] encJson = cipher.doFinal(bjson);
		String base64d = new String(org.bouncycastle.util.encoders.Base64.encode(encJson));
		
		Token token = new Token();
		token.setEncryptedRequest(base64d);
		token.setIv(new String(org.bouncycastle.util.encoders.Base64.encode(cipher.getIV())));
		
		
		
		String header = gson.toJson(token);
		
		
		
		byte[] btoken = header.getBytes("UTF-8");
		String encHeader = new String(org.bouncycastle.util.encoders.Base64.encode(btoken));
		return encHeader;
	}
	
	public void loadLastMielToken(String header,SecretKey decrKey) throws Exception {
		String tokenHeader = new String(org.bouncycastle.util.encoders.Base64.decode(header));
		Gson gson = new Gson();
		this.token = gson.fromJson(tokenHeader, Token.class);
		byte[] iv = org.bouncycastle.util.encoders.Base64.decode(this.token.getIv());
		
		
	    IvParameterSpec spec =  new IvParameterSpec(iv);
	    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, decrKey,spec);
	    
		byte[] encBytes = org.bouncycastle.util.encoders.Base64.decode(token.getEncryptedRequest());
		String requestToken = new String(cipher.doFinal(encBytes));
		
		////System.out.println(requestToken);
		
		this.request = gson.fromJson(requestToken, Request.class);
		
		int index = this.request.getUri().indexOf(";jsessionid=");
		if (index > 0) {
			this.altURI = (this.request.getUri().substring(0,index));
		}
	}
}