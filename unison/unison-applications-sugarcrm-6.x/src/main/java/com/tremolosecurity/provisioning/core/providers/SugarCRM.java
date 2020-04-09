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


package com.tremolosecurity.provisioning.core.providers;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.List;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.params.ClientPNames;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.cookie.Cookie;
import org.apache.http.cookie.CookieOrigin;
import org.apache.http.cookie.CookieSpec;
import org.apache.http.cookie.CookieSpecFactory;
import org.apache.http.cookie.MalformedCookieException;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.impl.cookie.BrowserCompatSpec;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.params.HttpParams;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;

import com.google.gson.Gson;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.UserStoreProvider;
import com.tremolosecurity.provisioning.core.providers.sugarcrm.SugarContactEntry;
import com.tremolosecurity.provisioning.core.providers.sugarcrm.SugarEntry;
import com.tremolosecurity.provisioning.core.providers.sugarcrm.SugarEntrySet;
import com.tremolosecurity.provisioning.core.providers.sugarcrm.SugarGetEntry;
import com.tremolosecurity.provisioning.core.providers.sugarcrm.SugarGetEntryList;
import com.tremolosecurity.provisioning.core.providers.sugarcrm.SugarID;
import com.tremolosecurity.provisioning.core.providers.sugarcrm.SugarLogin;
import com.tremolosecurity.provisioning.core.providers.sugarcrm.SugarResult;
import com.tremolosecurity.provisioning.core.providers.sugarcrm.UserAuth;
import com.tremolosecurity.saml.Attribute;

import com.tremolosecurity.util.NVP;


public class SugarCRM implements UserStoreProvider {

	String url;
	String userName;
	String password;

	String lookupAttribute;
	private ConfigManager cfgMgr;
	
	String name;
	
	private PoolingHttpClientConnectionManager phcm;
	private CloseableHttpClient httpClient;

	
	
	
	@Override
	public void createUser(User user, Set<String> attributes,Map<String,Object> request)
			throws ProvisioningException {
		ModuleType mt = this.getModuleType(request);
		
		int userID = 0;
		int approvalID = 0;
		int workflow = 0;
		
		if (request.containsKey("TREMOLO_USER_ID")) {
			userID = (Integer) request.get("TREMOLO_USER_ID");
		}
		
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		if (request.containsKey("WORKFLOW_ID")) {
			workflow = (Integer) request.get("WORKFLOW_ID");
		}
		
		try {
			
			String sessionId = sugarLogin();
			Gson gson = new Gson();
			
			SugarEntry newContact = new SugarEntry();
			newContact.setSession(sessionId);
			newContact.setModule(mt.name);
			Map<String,String> nvps = new HashMap<String,String>();
			
			for (String attrName : user.getAttribs().keySet()) {
				if (! attributes.contains(attrName) || attrName.equalsIgnoreCase("userName")) {
					continue;
				}
				
				
				if (attrName.equalsIgnoreCase("account_name")) {
					String id = this.getAccountId(user.getAttribs().get(attrName).getValues().get(0), sessionId);
					nvps.put("account_id", id);
				}
				nvps.put(attrName, user.getAttribs().get(attrName).getValues().get(0));
			}
			
			newContact.setName_value_list(nvps);
			String createUserJSON = gson.toJson(newContact);
			
			execJson(createUserJSON,"set_entry");
			
			
			
			
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not find user", e);
		}

	}

	@Override
	public void syncUser(User user, boolean addOnly, Set<String> attributes,Map<String,Object> request)
			throws ProvisioningException {
		
		ModuleType mt = this.getModuleType(request);
		
		int userID = 0;
		int approvalID = 0;
		int workflow = 0;
		
		if (request.containsKey("TREMOLO_USER_ID")) {
			userID = (Integer) request.get("TREMOLO_USER_ID");
		}
		
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		if (request.containsKey("WORKFLOW_ID")) {
			workflow = (Integer) request.get("WORKFLOW_ID");
		}
		
		try {
			
			String sessionId = sugarLogin();
			
			Map<String,String> toAdd = new HashMap<String,String>();
			Map<String,String> toReplace = new HashMap<String,String>();
			Map<String,String> toDelete = new HashMap<String,String>();
			
			Gson gson = new Gson();
			
			Set<String> nattribs = new HashSet<String>();
			nattribs.addAll(attributes);
			nattribs.add("id");
			
			User foundUser = null;
			
			try {
				foundUser = this.findUser(user.getUserID(), nattribs,request);
			} catch (Exception e) {
				this.createUser(user, attributes,request);
				return;
			}
			
			Map<String,String> nvps = new HashMap<String,String>();
			nvps.put("id", foundUser.getAttribs().get("id").getValues().get(0));
			
			for (String attrName : user.getAttribs().keySet()) {
				if (! attributes.contains(attrName)) {
					continue;
				}
				
				if (attrName.equalsIgnoreCase("account_name")) {
					String id = this.getAccountId(user.getAttribs().get(attrName).getValues().get(0), sessionId);
					nvps.put("account_id", id);
				}
				
				foundUser.getAttribs().put(attrName, new Attribute(attrName,user.getAttribs().get(attrName).getValues().get(0)));
			}
			
			if (! addOnly) {
				for (String attrName : foundUser.getAttribs().keySet()) {
					if (! user.getAttribs().containsKey(attrName) && ! attributes.contains(attrName) && ! attrName.equalsIgnoreCase("id")) {
						foundUser.getAttribs().put(attrName, new Attribute(attrName,""));
					}
				}
			}
			
			for (String attrName : foundUser.getAttribs().keySet()) {
				nvps.put(attrName, foundUser.getAttribs().get(attrName).getValues().get(0));
			}
			
			SugarEntry newContact = new SugarEntry();
			newContact.setSession(sessionId);
			newContact.setModule(mt.name);
			
			
			newContact.setName_value_list(nvps);
			String createUserJSON = gson.toJson(newContact);
			
			execJson(createUserJSON,"set_entry");
		} catch (Exception e) {
			throw new ProvisioningException("Could not sync user",e);
		}
	}

	@Override
	public void deleteUser(User user,Map<String,Object> request) throws ProvisioningException {
		try {
			
			ModuleType mt = this.getModuleType(request);
			
			String sessionId = sugarLogin();
			Gson gson = new Gson();

			SugarGetEntryList sgel = new SugarGetEntryList();
			sgel.setSession(sessionId);
			sgel.setModule_name(mt.name);
			StringBuffer b = new StringBuffer();
			b.append(mt.lookupByEmail).append(user.getUserID()).append("')");
			sgel.setQuery(b.toString());
			sgel.setOrder_by("");
			sgel.setOffset(0);
			ArrayList<String> reqFields = new ArrayList<String>();
			reqFields.add("id");
			sgel.setSelect_fields(reqFields);
			sgel.setMax_results(-1);
			sgel.setDeleted(false);
			sgel.setLink_name_to_fields_array(new HashMap<String, List<String>>());

			String searchJson = gson.toJson(sgel);
			String respJSON = execJson(searchJson, "get_entry_list");
			JSONObject jsonObj = (JSONObject) JSONValue.parse(respJSON);
			JSONArray jsonArray = (JSONArray) jsonObj.get("entry_list");
			
			if (jsonArray.size() == 0) {
				throw new Exception("User " + user.getUserID() + " not found");
			}
			
			String id = (String) ((JSONObject) jsonArray.get(0)).get("id");
			
			SugarEntry newContact = new SugarEntry();
			newContact.setSession(sessionId);
			newContact.setModule(mt.name);
			Map<String,String> nvps = new HashMap<String,String>();
			nvps.put("id", id);
			nvps.put("deleted", "1");
			
			newContact.setName_value_list(nvps);
			String createUserJSON = gson.toJson(newContact);
			
			execJson(createUserJSON,"set_entry");
		} catch (Exception e) {
			throw new ProvisioningException("Could not delete user",e);
		}

	}
	
	public void deleteAccount(String name ) throws ProvisioningException {
		try {
			DefaultHttpClient http = new DefaultHttpClient();
			String sessionId = sugarLogin();
			Gson gson = new Gson();

			String id = this.getAccountId(name, sessionId);
			SugarEntry newContact = new SugarEntry();
			newContact.setSession(sessionId);
			newContact.setModule("Accounts");
			Map<String,String> nvps = new HashMap<String,String>();
			nvps.put("id", id);
			nvps.put("deleted", "1");
			
			newContact.setName_value_list(nvps);
			String createUserJSON = gson.toJson(newContact);
			
			execJson(createUserJSON,"set_entry");
		} catch (Exception e) {
			throw new ProvisioningException("Could not delete user",e);
		}

	}

	@Override
	public User findUser(String userID, Set<String> attributes,Map<String,Object> request)
			throws ProvisioningException {

		try {
			ModuleType mt = this.getModuleType(request);
			
			String sessionId = sugarLogin();
			Gson gson = new Gson();

			SugarGetEntryList sgel = new SugarGetEntryList();
			sgel.setSession(sessionId);
			sgel.setModule_name(mt.name);
			StringBuffer b = new StringBuffer();
			b.append(mt.lookupByEmail).append(userID).append("')");
			sgel.setQuery(b.toString());
			sgel.setOrder_by("");
			sgel.setOffset(0);
			ArrayList<String> reqFields = new ArrayList<String>();
			reqFields.add("id");
			sgel.setSelect_fields(reqFields);
			sgel.setMax_results(-1);
			sgel.setDeleted(false);
			sgel.setLink_name_to_fields_array(new HashMap<String, List<String>>());

			String searchJson = gson.toJson(sgel);
			
			String respJSON = execJson(searchJson, "get_entry_list");
			
			JSONObject jsonObj = (JSONObject) JSONValue.parse(respJSON);
			JSONArray jsonArray = (JSONArray) jsonObj.get("entry_list");
			String id = (String) ((JSONObject) jsonArray.get(0)).get("id");

			SugarGetEntry sge = new SugarGetEntry();
			sge.setId(id);
			sge.setSession(sessionId);
			sge.setSelect_fields(new ArrayList<String>());
			sge.setModule_name(mt.name);
			sge.setLink_name_to_fields_array(new HashMap<String, List<String>>());
			searchJson = gson.toJson(sge);
			respJSON = execJson(searchJson, "get_entry");
			//System.out.println(respJSON);
			SugarEntrySet res = gson.fromJson(respJSON, SugarEntrySet.class);

			User user = new User(userID);

			SugarContactEntry sce = res.getEntry_list().get(0);
			for (String attrName : sce.getName_value_list().keySet()) {
				NVP nvp = sce.getName_value_list().get(attrName);

				if (attributes.size() > 0
						&& !attributes.contains(nvp.getName())) {
					continue;
				}

				if (nvp.getValue() != null && !nvp.getValue().isEmpty()) {
					Attribute attr = new Attribute(nvp.getName(),
							nvp.getValue());
					user.getAttribs().put(nvp.getName(), attr);
				}
			}

			return user;

		} catch (Exception e) {
			throw new ProvisioningException("Could not find user", e);
		}
	}

	private String sugarLogin()
			throws NoSuchAlgorithmException, Exception,
			UnsupportedEncodingException, IOException, ClientProtocolException {

		MessageDigest md = MessageDigest.getInstance("MD5");
		SugarLogin login = new SugarLogin();

		login.setUser_name(this.userName);
		login.setPassword(getHexString(md.digest(this.password
				.getBytes("UTF-8"))));

		UserAuth userAuth = new UserAuth();
		userAuth.setUser_auth(login);

		Gson gson = new Gson();
		String jsonLogin = gson.toJson(userAuth);

		String respJSON = execJson(jsonLogin, "login");
		JSONObject jsonObj = (JSONObject) JSONValue.parse(respJSON);
		return jsonObj.get("id").toString();
	}

	@Override
	public void init(Map<String, Attribute> cfg, ConfigManager cfgMgr,String name)
			throws ProvisioningException {
		this.name = name;
		this.url = cfg.get("url").getValues().get(0);
		this.userName = cfg.get("adminUser").getValues().get(0);
		this.password = cfg.get("adminPwd").getValues().get(0);
		
		this.cfgMgr = cfgMgr;
		phcm = new PoolingHttpClientConnectionManager(cfgMgr.getHttpClientSocketRegistry());
		httpClient = HttpClients.custom().setConnectionManager(phcm).build();
		
		

	}

	
	
	private String execJson(String jsonLogin, String method) throws UnsupportedEncodingException,
			IOException, ClientProtocolException, ProvisioningException {

		
		
		HttpPost httppost = new HttpPost(this.url);
		try {
			List<NameValuePair> formparams = new ArrayList<NameValuePair>();
			formparams.add(new BasicNameValuePair("method", method));
			formparams.add(new BasicNameValuePair("input_type", "json"));
			formparams.add(new BasicNameValuePair("response_type", "json"));
			formparams.add(new BasicNameValuePair("rest_data", jsonLogin));
			UrlEncodedFormEntity entity = new UrlEncodedFormEntity(formparams,
					"UTF-8");
	
			httppost.setEntity(entity);
	
			HttpResponse response = httpClient.execute(httppost);
	
			BufferedReader in = new BufferedReader(new InputStreamReader(response
					.getEntity().getContent()));
			StringBuffer resp = new StringBuffer();
			String line = null;
			while ((line = in.readLine()) != null) {
				resp.append(line);
			}
	
			
	
			String respJSON = resp.toString();
			return respJSON;
		} finally {
			httppost.releaseConnection();
		}
	}

	public static String getHexString(byte[] data) throws Exception {
		StringBuffer buf = new StringBuffer();
		for (int i = 0; i < data.length; i++) {
			int halfbyte = (data[i] >>> 4) & 0x0F;
			int two_halfs = 0;
			do {
				if ((0 <= halfbyte) && (halfbyte <= 9))
					buf.append((char) ('0' + halfbyte));
				else
					buf.append((char) ('a' + (halfbyte - 10)));
				halfbyte = data[i] & 0x0F;
			} while (two_halfs++ < 1);
		}
		return buf.toString();
	}
	
	private String getAccountId(String name,String sessionId) throws UnsupportedEncodingException, ClientProtocolException, IOException, ProvisioningException {
		Gson gson = new Gson();
		SugarGetEntryList sgel = new SugarGetEntryList();
		sgel.setSession(sessionId);
		sgel.setModule_name("Accounts");
		StringBuffer b = new StringBuffer();
		b.append("accounts.name='").append(name).append("'");
		sgel.setQuery(b.toString());
		sgel.setOrder_by("");
		sgel.setOffset(0);
		ArrayList<String> reqFields = new ArrayList<String>();
		reqFields.add("id");
		sgel.setSelect_fields(reqFields);
		sgel.setMax_results(-1);
		sgel.setDeleted(false);
		sgel.setLink_name_to_fields_array(new HashMap<String,List<String>>());
		
		String companyLookupJSON = gson.toJson(sgel);
		
		
		String respJSON = execJson(companyLookupJSON,"get_entry_list");
		
		
		SugarResult sr = gson.fromJson(respJSON, SugarResult.class);
		
		if (sr.getResult_count() == 0) {
			SugarEntry newContact = new SugarEntry();
			newContact.setSession(sessionId);
			newContact.setModule("Accounts");
			Map<String,String> nvps = new HashMap<String,String>();
			nvps.put("name", name);
			newContact.setName_value_list(nvps);
			String createUserJSON = gson.toJson(newContact);
			
			respJSON = execJson(createUserJSON,"set_entry");
			
			SugarID id = gson.fromJson(respJSON, SugarID.class);
			return id.getId();
		} else {
			return sr.getEntry_list().get(0).getId();
		}
		
		
	}

	@Override
	public void setUserPassword(User user,Map<String,Object> request) throws ProvisioningException {
		// TODO Auto-generated method stub
		
	}
	
	private ModuleType getModuleType(Map<String,Object> request) throws ProvisioningException {
		if (request.get("tremoloio.sugarcrm.module") == null || request.get("tremoloio.sugarcrm.module").equals("contacts")) {
			ModuleType mt = new ModuleType();
			mt.name = "Contacts";
			mt.lookupByEmail = "contacts.id in (SELECT eabr.bean_id FROM email_addr_bean_rel eabr JOIN email_addresses ea ON (ea.id = eabr.email_address_id) WHERE eabr.deleted=0 AND ea.email_address = '";
			return mt;
		} else if (request.get("tremoloio.sugarcrm.module").equals("leads")) {
			ModuleType mt = new ModuleType();
			mt.name = "Leads";
			mt.lookupByEmail = "leads.id in (SELECT eabr.bean_id FROM email_addr_bean_rel eabr JOIN email_addresses ea ON (ea.id = eabr.email_address_id) WHERE eabr.deleted=0 AND ea.email_address = '";
			return mt;
		}
		
		else {
			throw new ProvisioningException("Unknown module '" + request.get("tremoloio.sugarcrm.module") + "'");
		}
	}
}

class ModuleType {
	String name;
	String lookupByEmail;
}
