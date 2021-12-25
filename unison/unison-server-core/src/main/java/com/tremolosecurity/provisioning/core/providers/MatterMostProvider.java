/*******************************************************************************
 * Copyright 2020 Tremolo Security, Inc.
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
package com.tremolosecurity.provisioning.core.providers;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.message.BasicHeader;
import org.apache.http.util.EntityUtils;
import org.apache.log4j.Logger;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.UserStoreProvider;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.provisioning.util.GenPasswd;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;

public class MatterMostProvider implements UserStoreProvider {
	
	static Logger logger = Logger.getLogger(MatterMostProvider.class);

	String oauth2Token;
	ConfigManager cfgMgr;
	String matterMostUrl;

	private String name;
	
	@Override
	public void createUser(User user, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		String userID = user.getUserID();
		HttpCon con = null;
		
		try {
			con = this.createClient();
			
			JSONObject newUser = new JSONObject();
			
			for (String attribute : attributes) {
				Attribute attr = user.getAttribs().get(attribute);
				if (attr != null) {
					newUser.put(attr.getName(), attr.getValues().get(0));
				}
			}
			
			StringBuilder sb = new StringBuilder();
			for (String group : user.getGroups()) {
				sb.append(group).append(' ');
			}
			
			String groups = sb.toString().trim();
			if (! groups.isEmpty()) {
				newUser.put("roles", groups);
			}
			
			if (user.getPassword() != null) {
				//user.setPassword(new GenPasswd(25,true,true,true,true).getPassword());
				newUser.put("password", user.getPassword());
			}
			
			
			
			this.callWSPost(con, "/api/v4/users", newUser.toString());
			
			this.cfgMgr.getProvisioningEngine().logAction(this.name,true, ActionType.Add,  approvalID, workflow, "username", userID);
			
			
			
			for (String attribute : attributes) {
				Attribute attr = user.getAttribs().get(attribute);
				if (attr != null) {
					this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Add,  approvalID, workflow, attr.getName(), attr.getValues().get(0));
				}
			}
			
			if (user.getPassword() != null) {
				this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Add,  approvalID, workflow, "password", "*******");
			}
			
			for (String group : user.getGroups()) {
				this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Add,  approvalID, workflow, "role", group);
			}
			
			
		} catch (Exception  e) {
			throw new ProvisioningException("Could create '" + userID + "'",e);
		}  finally {
			if (con != null) {
				try {
					con.getHttp().close();
				} catch (IOException e) {
					
				}
				
				con.getBcm().close();
			}
		}

	}

	@Override
	public void setUserPassword(User user, Map<String, Object> request) throws ProvisioningException {
		// TODO Auto-generated method stub

	}

	@Override
	public void syncUser(User user, boolean addOnly, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		
		user.setUserID(user.getUserID().toLowerCase());
		
		if (user.getAttribs().get("email") != null) {
			String emailAddress = user.getAttribs().get("email").getValues().get(0).toLowerCase();
			user.getAttribs().get("email").getValues().clear();
			user.getAttribs().get("email").getValues().add(emailAddress);
		}
		
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		StringBuilder sb = new StringBuilder();
		
		HttpCon con = null;
		
		try {
			con = this.createClient();
			
			JSONObject mmUser = loadUserJson(user.getUserID(), con);
			
			if (mmUser == null) {
				this.createUser(user, attributes, request);
				return;
			}
			
			HashMap<String,String> updates = new HashMap<String,String>();
			HashMap<String,String> adds = new HashMap<String,String>();
			
			List<String> groupsAdded = new ArrayList<String>();
			List<String> groupsRemoved = new ArrayList<String>();
			
			for (String attributeName : attributes) {
				String attrValue = user.getAttribs().get(attributeName).getValues().get(0);
				
				if (attrValue != null) {
					Object attrFromMM = mmUser.get(attributeName);
					if (attrFromMM == null) {
						adds.put(attributeName, attrValue);
						mmUser.put(attributeName, attrValue);
					} else if (! attrFromMM.equals(attrValue)) {
						updates.put(attributeName, attrValue);
						mmUser.put(attributeName, attrValue);
					}
				}
			}
			
		
			sb.setLength(0);
			StringTokenizer toker = new StringTokenizer(mmUser.get("roles").toString().trim()," ",false);
			HashSet<String> groups = new HashSet<String>();
			while (toker.hasMoreTokens()) {
				groups.add(toker.nextToken());
			}
			
			for (String group : user.getGroups()) {
				if (! groups.contains(group)) {
					groups.add(group);
					groupsAdded.add(group);
				}
			}
			
			if (! addOnly) {
				for (String group : groups) {
					if (! user.getGroups().contains(group)) {
						groupsRemoved.add(group);
					}
				}
				
				for (String group : groupsRemoved) {
					groups.remove(group);
				}
			}
			
			for (String group : groups) {
				sb.append(group).append(' ');
			}
				
			String newRoles = sb.toString().trim();
			
			sb.setLength(0);
			
			sb.append("/api/v4/users/").append(mmUser.get("id").toString()).append("/patch");
			
			String jsonFromMatterMost = this.callWSPut(con, sb.toString(),mmUser.toString());
			
			
			
			if (! newRoles.equals(mmUser.get("roles"))) {
				sb.setLength(0);
				
				sb.append("/api/v4/users/").append(mmUser.get("id").toString()).append("/roles");
				
				JSONObject rolesObj = new JSONObject();
				rolesObj.put("roles", newRoles);
				
				jsonFromMatterMost = this.callWSPut(con, sb.toString(),rolesObj.toString());
			}
			
			for (String attrName : updates.keySet()) {
				this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Replace,  approvalID, workflow, attrName, updates.get(attrName));
			}
			
			for (String attrName : adds.keySet()) {
				this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Add,  approvalID, workflow, attrName, adds.get(attrName));
			}
			
			for (String group : groupsAdded) {
				this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Add,  approvalID, workflow, "role", group);
			}
			
			for (String group : groupsRemoved) {
				this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Delete,  approvalID, workflow, "role", group);
			}
			
			
			
		} catch (Exception  e) {
			throw new ProvisioningException("Could not sync '" + user.getUserID() + "'",e);
		}  finally {
			if (con != null) {
				try {
					con.getHttp().close();
				} catch (IOException e) {
					
				}
				
				con.getBcm().close();
			}
		}

	}

	@Override
	public void deleteUser(User user, Map<String, Object> request) throws ProvisioningException {
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		HashSet<String> attrs = new HashSet<String>();
		attrs.add("id");
		attrs.add("username");
		
		User fromServer = this.findUser(user.getUserID(), attrs, request);
		
		if (fromServer == null) {
			logger.warn("User '" + user.getUserID() + "' not found");
			return;
		}
		
		String id = fromServer.getAttribs().get("id").getValues().get(0);
		
		
		StringBuilder sb = new StringBuilder();
		sb.append("/api/v4/users/").append(id);
		
		HttpCon con = null;
		
		try {
			con = this.createClient();
			String jsonFromMatterMost = this.callDeleteWS(con, sb.toString());
			
			this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Replace,  approvalID, workflow, "delete_at", "0");
			
		} catch (Exception  e) {
			throw new ProvisioningException("Could not delete '" + user.getUserID() + "'",e);
		}  finally {
			if (con != null) {
				try {
					con.getHttp().close();
				} catch (IOException e) {
					
				}
				
				con.getBcm().close();
			}
		}
		

	}

	@Override
	public User findUser(String userID, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		
		userID = userID.toLowerCase();
		
		HttpCon con = null;
		
		try {
			con = this.createClient();
			JSONObject mmUser = loadUserJson(userID, con);
			
			if (mmUser == null) { 
				return null;
			}
			
			User user = new User(userID);
			for (String attribute : attributes) {
				Object val =  mmUser.get(attribute);
				if (val != null) {
					user.getAttribs().put(attribute, new Attribute(attribute,val.toString()));
				}
			}
			
			String groups = (String) mmUser.get("roles");
			if (groups != null) {
				StringTokenizer toker = new StringTokenizer(groups," ",false);
				while (toker.hasMoreTokens()) {
					user.getGroups().add(toker.nextToken());
				}
			}
			
			return user;
		} catch (Exception  e) {
			throw new ProvisioningException("Could not load '" + userID + "'",e);
		}  finally {
			if (con != null) {
				try {
					con.getHttp().close();
				} catch (IOException e) {
					
				}
				
				con.getBcm().close();
			}
		}
		
		
		
	}

	public JSONObject loadUserJson(String userID, HttpCon con)
			throws IOException, ClientProtocolException, ProvisioningException, ParseException {
		StringBuilder sb = new StringBuilder();
		sb.append("/api/v4/users/username/").append(userID);
		String jsonFromMatterMost = this.callWS(con, sb.toString());
		
		if (jsonFromMatterMost == null) {
			return null;
		}
		
		if (logger.isDebugEnabled()) {
			logger.debug("JSON of user : '" + jsonFromMatterMost + "'");
		}
		
		JSONObject mmUser = (JSONObject) new JSONParser().parse(jsonFromMatterMost);
		return mmUser;
	}

	@Override
	public void init(Map<String, Attribute> cfg, ConfigManager cfgMgr, String name) throws ProvisioningException {
		this.matterMostUrl = cfg.get("matterMostUrl").getValues().get(0);
		this.oauth2Token = cfg.get("accessToken").getValues().get(0);
		this.cfgMgr = cfgMgr;
		this.name = name;

	}

	@Override
	public void shutdown() throws ProvisioningException {
		// TODO Auto-generated method stub

	}
	
	public HttpCon createClient() throws Exception {
		ArrayList<Header> defheaders = new ArrayList<Header>();
		defheaders.add(new BasicHeader("X-Csrf-Token", "1"));

		BasicHttpClientConnectionManager bhcm = new BasicHttpClientConnectionManager(
				cfgMgr.getHttpClientSocketRegistry());

		RequestConfig rc = RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD).setRedirectsEnabled(false)
				.build();

		CloseableHttpClient http = HttpClients.custom()
				                  .setConnectionManager(bhcm)
				                  .setDefaultHeaders(defheaders)
				                  .setDefaultRequestConfig(rc)
				                  .build();

		HttpCon con = new HttpCon();
		con.setBcm(bhcm);
		con.setHttp(http);

		return con;

	}
	
	public String callWS(HttpCon con,String uri) throws IOException, ClientProtocolException, ProvisioningException {
		StringBuffer b = new StringBuffer();
		
		b.append(matterMostUrl).append(uri);
		HttpGet get = new HttpGet(b.toString());
		b.setLength(0);
		b.append("Bearer ").append(this.oauth2Token);
		get.addHeader(new BasicHeader("Authorization",b.toString()));
		HttpResponse resp = con.getHttp().execute(get);
		get.abort();
		String json = EntityUtils.toString(resp.getEntity());
		
		if (logger.isDebugEnabled()) {
			logger.debug("url : '" + uri + "'");
			logger.debug("Response Code : " + resp.getStatusLine().getStatusCode());
			logger.debug(json);
		}
		
		if (resp.getStatusLine().getStatusCode() == 404) {
			return null;
		} else {
			return json;
		}
		
		
		
	}
	
	public String callDeleteWS(HttpCon con,String uri) throws IOException, ClientProtocolException, ProvisioningException {
		StringBuffer b = new StringBuffer();
		
		b.append(matterMostUrl).append(uri);
		HttpDelete delete = new HttpDelete(b.toString());
		b.setLength(0);
		b.append("Bearer ").append(this.oauth2Token);
		delete.addHeader(new BasicHeader("Authorization",b.toString()));
		HttpResponse resp = con.getHttp().execute(delete);
		delete.abort();
		String json = EntityUtils.toString(resp.getEntity());
		
		if (logger.isDebugEnabled()) {
			logger.debug("url : '" + uri + "'");
			logger.debug("Response Code : " + resp.getStatusLine().getStatusCode());
			logger.debug(json);
		}
		
		if (resp.getStatusLine().getStatusCode() != 200) {
			throw new IOException("Delete failed " + EntityUtils.toString(resp.getEntity()));
		} else {
			return json;
		}
		
		
		
	}
	
	public String callWSPost(HttpCon con,String uri,String json) throws IOException, ClientProtocolException, ProvisioningException {
		StringBuffer b = new StringBuffer();
		
		b.append(this.matterMostUrl).append(uri);
		HttpPost put = new HttpPost(b.toString());
		b.setLength(0);
		b.append("Bearer ").append(this.oauth2Token);
		put.addHeader(new BasicHeader("Authorization",b.toString()));
		
		StringEntity str = new StringEntity(json,ContentType.create("application/json"));
		put.setEntity(str);
		
		HttpResponse resp = con.getHttp().execute(put);
		put.abort();
		if (resp.getStatusLine().getStatusCode() != 201) {
			
			
			if (logger.isDebugEnabled()) {
				logger.debug("url : '" + uri + "'");
				logger.debug("Response Code : " + resp.getStatusLine().getStatusCode());
				logger.debug(json);
			}
			
			
			throw new IOException("Post failed " + EntityUtils.toString(resp.getEntity()));
			
			
		} else {
			return EntityUtils.toString(resp.getEntity());
		}
		
		
	}
	
	public String callWSPut(HttpCon con,String uri,String json) throws IOException, ClientProtocolException, ProvisioningException {
		StringBuffer b = new StringBuffer();
		
		b.append(this.matterMostUrl).append(uri);
		HttpPut put = new HttpPut(b.toString());
		b.setLength(0);
		b.append("Bearer ").append(this.oauth2Token);
		put.addHeader(new BasicHeader("Authorization",b.toString()));
		
		StringEntity str = new StringEntity(json,ContentType.create("application/json"));
		put.setEntity(str);
		
		HttpResponse resp = con.getHttp().execute(put);
		put.abort();
		if (resp.getStatusLine().getStatusCode() != 200) {
			
			
			if (logger.isDebugEnabled()) {
				logger.debug("url : '" + uri + "'");
				logger.debug("Response Code : " + resp.getStatusLine().getStatusCode());
				logger.debug(json);
			}
			
			
			throw new IOException("Put failed " + EntityUtils.toString(resp.getEntity()));
			
			
		} else {
			return EntityUtils.toString(resp.getEntity());
		}
		
		
	}

}
