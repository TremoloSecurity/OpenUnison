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

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.util.Base64Util;

public class WebAuthnUserData implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = -3506362272344388035L;
	
	
	byte[] id;
	String displayName;
	
	List<OpenUnisonAuthenticator> authenticators;
	
	public WebAuthnUserData(String displayName) {
		this.displayName = displayName;
		this.id = new DefaultChallenge().getValue();
		this.authenticators = new ArrayList<OpenUnisonAuthenticator>();
	}
	
	private WebAuthnUserData() {
		this.authenticators = new ArrayList<OpenUnisonAuthenticator>();
	}

	public byte[] getId() {
		return id;
	}
	
	private void setId(byte[] id) {
		this.id = id;
	}

	public String getDisplayName() {
		return displayName;
	}
	
	private void setDisplayName(String displayName) {
		this.displayName = displayName;
	}

	public List<OpenUnisonAuthenticator> getAuthenticators() {
		return authenticators;
	}
	
	
	public byte[] serialize() {
		JSONObject  root = new JSONObject();
		
		root.put("id", Base64Util.encodeToString(this.id));
		root.put("displayName",this.displayName);
		
		JSONArray serAuths = new JSONArray();
		
		for (OpenUnisonAuthenticator ouAuth : this.authenticators) {
			serAuths.add(ouAuth.serialize());
		}
		
		root.put("authenticators",serAuths);
		
		try {
			return root.toString().getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			return null;
		}
	}
	
	public static WebAuthnUserData deserialize(JSONObject root) {
		WebAuthnUserData ret = new WebAuthnUserData();
		
		ret.setId(Base64Util.decode((String) root.get("id")));
		ret.setDisplayName((String) root.get("displayName"));
		
		JSONArray auths = (JSONArray) root.get("authenticators");
		for (Object o : auths) {
			try {
				ret.getAuthenticators().add(OpenUnisonAuthenticator.deserialize((JSONObject) o));
			} catch (ParseException e) {
				//can't happen
			}
		}
		
		return ret;
	}
	
}
