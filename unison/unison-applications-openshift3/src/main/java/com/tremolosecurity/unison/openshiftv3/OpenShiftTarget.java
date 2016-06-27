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
package com.tremolosecurity.unison.openshiftv3;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.net.util.Base64;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
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
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.apache.logging.log4j.Logger;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.UserStoreProvider;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.unison.openshiftv3.model.Response;
import com.tremolosecurity.unison.openshiftv3.model.groups.GroupItem;

public class OpenShiftTarget implements UserStoreProvider {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(OpenShiftTarget.class.getName());

	String url;
	String userName;
	String password;

	private ConfigManager cfgMgr;

	private String name;

	@Override
	public void createUser(User user, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		com.tremolosecurity.unison.openshiftv3.model.users.User osUser = new com.tremolosecurity.unison.openshiftv3.model.users.User();
		
		
		osUser.setKind("User");
		osUser.setApiVersion("v1");
		osUser.getMetadata().put("name", user.getUserID());
		if (user.getAttribs().get("fullName") != null) {
			osUser.setFullName(user.getAttribs().get("fullName").getValues().get(0));
		}
		
		Gson gson  = new Gson();
		
		try {
			String token = this.getAuthToken();
			
			
			HttpCon con = this.createClient();
			try {
				String json = gson.toJson(osUser);
				StringBuffer b = new StringBuffer();
				b.append("/oapi/v1/users");
				osUser = gson.fromJson(this.callWSPost(token, con, b.toString(), json),com.tremolosecurity.unison.openshiftv3.model.users.User.class);
				
				if (! osUser.getKind().equals("User")) {
					throw new ProvisioningException("Could not create user " + user.getUserID() + " - " + osUser.getReason());
				}
				
		
				this.cfgMgr.getProvisioningEngine().logAction(name,true, ActionType.Add,  approvalID, workflow, "name", user.getUserID());
				this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Add,  approvalID, workflow, "name", osUser.getMetadata().get("name"));
				
				if (user.getAttribs().get("fullName") != null) {
					this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Add,  approvalID, workflow, "fullName", osUser.getFullName());
				}
				
				
				
				
				
				for (String groupName : user.getGroups()) {
					this.addUserToGroup(token, con, user.getUserID(), groupName, approvalID, workflow);
				}
				
			} finally {
				if (con != null) {
					con.getBcm().shutdown();
				}
			}
		} catch (Exception e) {
			throw new ProvisioningException("Could not create user",e);
		}
		

	}

	@Override
	public void setUserPassword(User user, Map<String, Object> request) throws ProvisioningException {
		throw new ProvisioningException("Not supported");

	}

	@Override
	public void syncUser(User user, boolean addOnly, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		Gson gson = new Gson();
		User fromServer = this.findUser(user.getUserID(), attributes, request);
		if (fromServer == null) {
			this.createUser(user, attributes, request);
		} else {
			StringBuffer b = new StringBuffer();
			String token = null;
			
			if (attributes.contains("fullName")) {
				if (user.getAttribs().get("fullName") != null) {
					String fullName = user.getAttribs().get("fullName").getValues().get(0);
					String fromServerFullName = fromServer.getAttribs().get("fullName").getValues().get(0);
					
					if (! fromServerFullName.equalsIgnoreCase(fullName)) {
						try {
							token = setFullName(user, approvalID, workflow, gson, b);
						} catch (Exception e) {
							throw new ProvisioningException("Could not set fullName from " + user.getUserID(),e);
						}
					}
				} else {
					if (! addOnly) {
						try {
							token = deleteFullName(user, approvalID, workflow, gson, b);
						} catch (Exception e) {
							throw new ProvisioningException("Could not delete fullName from " + user.getUserID(),e);
						}
					}
				}
			}
			
			
			
			try {
				syncGroups(user, addOnly, approvalID, workflow, fromServer, token);
			} catch (Exception e) {
				throw new ProvisioningException("Could not sync groups for " + user.getUserID(),e);
			}
			
		}

	}

	private void syncGroups(User user, boolean addOnly, int approvalID, Workflow workflow, User fromServer,
			String token) throws Exception, IOException {
		HttpCon con = null;
		
		try {
			//first see if there are groups to add
			HashSet<String> fromServerGroups = new HashSet<String>();
			fromServerGroups.addAll(fromServer.getGroups());
			for (String groupName : user.getGroups()) {
				if (! fromServerGroups.contains(groupName)) {
					
					if (token == null) {
						token = this.getAuthToken();
					}
					
					if (con == null) {
						con = this.createClient();
					}
					
					this.addUserToGroup(token, con, user.getUserID(), groupName, approvalID, workflow);
				}
			}
			
			if (! addOnly) {
				//remove groups no longer present
				HashSet<String> fromUserGroups = new HashSet<String>();
				fromUserGroups.addAll(user.getGroups());
				
				for (String groupName : fromServer.getGroups()) {
					if (! fromUserGroups.contains(groupName)) {
						if (token == null) {
							token = this.getAuthToken();
						}
						
						if (con == null) {
							con = this.createClient();
						}
						
						this.removeUserFromGroup(token, con, user.getUserID(), groupName, approvalID, workflow);
					}
				}
			}
			
			
		} finally {
			if (con != null) {
				con.getBcm().shutdown();
				con.getHttp().close();
			}
		}
	}

	private String deleteFullName(User user, int approvalID, Workflow workflow, Gson gson, StringBuffer b)
			throws Exception, IOException, ClientProtocolException, ProvisioningException {
		String token;
		token = this.getAuthToken();
		HttpCon con = this.createClient();
		try {
			b.append("/oapi/v1/users/").append(user.getUserID());
			String json = callWS(token,con,b.toString());
			com.tremolosecurity.unison.openshiftv3.model.users.User osUser = gson.fromJson(json, com.tremolosecurity.unison.openshiftv3.model.users.User.class);
			osUser.setFullName(null);
			json = gson.toJson(osUser);
			json = callWSPut(token,con,b.toString(),json);
			osUser = gson.fromJson(json, com.tremolosecurity.unison.openshiftv3.model.users.User.class);
			
			if (osUser.getKind().equals("User")) {
				this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Delete,  approvalID, workflow, "fullName", osUser.getFullName());
			} else {
				throw new Exception("Could not unset fullName for " + user.getUserID() + " - " + osUser.getReason());
			}
			
		} finally {
			
			con.getHttp().close();
			con.getBcm().shutdown();
		}
		
		return token;
	}
	
	
	private String setFullName(User user, int approvalID, Workflow workflow, Gson gson, StringBuffer b)
			throws Exception, IOException, ClientProtocolException, ProvisioningException {
		String token;
		token = this.getAuthToken();
		HttpCon con = this.createClient();
		try {
			b.append("/oapi/v1/users/").append(user.getUserID());
			String json = callWS(token,con,b.toString());
			com.tremolosecurity.unison.openshiftv3.model.users.User osUser = gson.fromJson(json, com.tremolosecurity.unison.openshiftv3.model.users.User.class);
			osUser.setFullName(user.getAttribs().get("fullName").getValues().get(0));
			json = gson.toJson(osUser);
			json = callWSPut(token,con,b.toString(),json);
			osUser = gson.fromJson(json, com.tremolosecurity.unison.openshiftv3.model.users.User.class);
			
			if (osUser.getKind().equals("User")) {
				this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Replace,  approvalID, workflow, "fullName", osUser.getFullName());
			} else {
				throw new Exception("Could not set fullName for " + user.getUserID() + " - " + osUser.getReason());
			}
			
		} finally {
			
			con.getHttp().close();
			con.getBcm().shutdown();
		}
		
		return token;
	}

	@Override
	public void deleteUser(User user, Map<String, Object> request) throws ProvisioningException {
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		user = this.findUser(user.getUserID(), new HashSet<String>(), request);
		
		try {
			String token = this.getAuthToken();
			HttpCon con = this.createClient();
			Gson gson = new Gson();
			try {
				StringBuffer b = new StringBuffer();
				b.append("/oapi/v1/users/").append(user.getUserID());
				String json = this.callWSDelete(token, con, b.toString());
				Response resp = gson.fromJson(json, Response.class);
				if (resp.getCode() != 200) {
					throw new Exception("Unable to delete " + user.getUserID() + " - " + resp.getReason());
				}
				
				this.cfgMgr.getProvisioningEngine().logAction(name,true, ActionType.Delete,  approvalID, workflow, "name", user.getUserID());
				
				for (String group : user.getGroups()) {
					this.removeUserFromGroup(token, con, user.getUserID(), group, approvalID, workflow);
				}
			} finally {
				if (con != null) {
					con.getBcm().shutdown();
					con.getHttp().close();
				}
			}
		} catch (Exception e) {
			throw new ProvisioningException("Could not delete user " + user.getUserID());
		} 
	}

	@Override
	public User findUser(String userID, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		try {
			User user = null;
			String token = this.getAuthToken();
			
			//users aren't bound to groups and there's no way to directly lookup what groups a user has
			//so we need to read all groups and see if the user exists
			
			ArrayList<String> groupsForUser = new ArrayList<String>();
			HttpCon con = this.createClient();
			StringBuffer b = new StringBuffer();
			
			com.tremolosecurity.unison.openshiftv3.model.List<GroupItem> groupList = null;
			
			try {
				
				String json = callWS(token, con,"/oapi/v1/groups");
				Gson gson = new Gson();
				TypeToken<com.tremolosecurity.unison.openshiftv3.model.List<GroupItem>> tokenType = new TypeToken<com.tremolosecurity.unison.openshiftv3.model.List<GroupItem>>() {};
				groupList = gson.fromJson(json, tokenType.getType());
				
				b.append("/oapi/v1/users/").append(userID);
				json = callWS(token,con,b.toString());
				
				
				com.tremolosecurity.unison.openshiftv3.model.users.User osUser = gson.fromJson(json, com.tremolosecurity.unison.openshiftv3.model.users.User.class);
				
				if (osUser.getKind().equalsIgnoreCase("User")) {
				
					user = new User(userID);
					
					for (String attrName : osUser.getMetadata().keySet()) {
						if (! attrName.equalsIgnoreCase("fullName") && attributes.contains(attrName)) {
							user.getAttribs().put(attrName, new Attribute(attrName,osUser.getMetadata().get(attrName)));
						}
					}
					
					if (attributes.contains("fullName") && osUser.getFullName() != null) {
						user.getAttribs().put("fullName", new Attribute("fullName",osUser.getFullName()));
					}
				}
				
			} finally {
				if (con != null) {
					con.getBcm().shutdown();
				}
			}
			
			for (GroupItem group : groupList.getItems()) {
				if (group.getUsers() != null && group.getUsers().contains(userID)) {
					groupsForUser.add((String) group.getMetadata().get("name"));
				}
			}
			
			if (groupsForUser.isEmpty()) {
				return user;
			} else {
				if (user == null) {
					user = new User(userID);
				}
				user.getGroups().addAll(groupsForUser);
				return user;
			}
		} catch (Exception e) {
			throw new ProvisioningException("Could not load " + userID,e);
		}
	}

	public String callWS(String token, HttpCon con,String uri) throws IOException, ClientProtocolException {
		StringBuffer b = new StringBuffer();
		
		b.append(this.url).append(uri);
		HttpGet get = new HttpGet(b.toString());
		b.setLength(0);
		b.append("Bearer ").append(token);
		get.addHeader(new BasicHeader("Authorization","Bearer " + token));
		HttpResponse resp = con.getHttp().execute(get);
		
		String json = EntityUtils.toString(resp.getEntity());
		return json;
	}
	
	private String callWSDelete(String token, HttpCon con,String uri) throws IOException, ClientProtocolException {
		StringBuffer b = new StringBuffer();
		
		b.append(this.url).append(uri);
		HttpDelete get = new HttpDelete(b.toString());
		b.setLength(0);
		b.append("Bearer ").append(token);
		get.addHeader(new BasicHeader("Authorization","Bearer " + token));
		HttpResponse resp = con.getHttp().execute(get);
		
		String json = EntityUtils.toString(resp.getEntity());
		return json;
	}
	
	private String callWSPut(String token, HttpCon con,String uri,String json) throws IOException, ClientProtocolException {
		StringBuffer b = new StringBuffer();
		
		b.append(this.url).append(uri);
		HttpPut put = new HttpPut(b.toString());
		b.setLength(0);
		b.append("Bearer ").append(token);
		put.addHeader(new BasicHeader("Authorization","Bearer " + token));
		
		StringEntity str = new StringEntity(json,ContentType.APPLICATION_JSON);
		put.setEntity(str);
		
		HttpResponse resp = con.getHttp().execute(put);
		
		json = EntityUtils.toString(resp.getEntity());
		return json;
	}
	
	private String callWSPost(String token, HttpCon con,String uri,String json) throws IOException, ClientProtocolException {
		StringBuffer b = new StringBuffer();
		
		b.append(this.url).append(uri);
		HttpPost put = new HttpPost(b.toString());
		b.setLength(0);
		b.append("Bearer ").append(token);
		put.addHeader(new BasicHeader("Authorization","Bearer " + token));
		
		StringEntity str = new StringEntity(json,ContentType.APPLICATION_JSON);
		put.setEntity(str);
		
		HttpResponse resp = con.getHttp().execute(put);
		
		json = EntityUtils.toString(resp.getEntity());
		return json;
	}

	@Override
	public void init(Map<String, Attribute> cfg, ConfigManager cfgMgr, String name) throws ProvisioningException {
		this.url = this.loadOption("url", cfg, false);
		this.userName = this.loadOption("userName", cfg, false);
		this.password = this.loadOption("password", cfg, true);

		this.cfgMgr = cfgMgr;
		this.name = name;

	}

	private String loadOption(String name, Map<String, Attribute> cfg, boolean mask) throws ProvisioningException {
		if (!cfg.containsKey(name)) {
			throw new ProvisioningException(name + " is required");
		} else {
			String val = cfg.get(name).getValues().get(0);
			if (!mask) {
				logger.info("Config " + name + "='" + val + "'");
			} else {
				logger.info("Config " + name + "='*****'");
			}

			return val;
		}
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

	public String getAuthToken() throws Exception {
		HttpCon con = this.createClient();
		try {
			StringBuffer b = new StringBuffer();
			b.append(this.url).append("/oauth/authorize?response_type=token&client_id=openshift-challenging-client");
			HttpGet get = new HttpGet(b.toString());
			b.setLength(0);
			b.append(this.userName).append(':').append(this.password);
			String b64 = Base64.encodeBase64String(b.toString().getBytes("UTF-8"));
			b.setLength(0);
			b.append("Basic ").append(b64.substring(0, b64.length() - 2));
			get.addHeader(new BasicHeader("Authorization",b.toString()));
			
			HttpResponse resp = con.getHttp().execute(get);
			String token = "";
			if (resp.getStatusLine().getStatusCode() == 302) {
				String url = resp.getFirstHeader("Location").getValue();
				int start = url.indexOf("access_token") + "access_token=".length();
				int end = url.indexOf("&",start + 1);
				token = url.substring(start, end);
				
			} else {
				throw new Exception("Unable to obtain token : " + resp.getStatusLine().toString());
			}
			
			
			
			return token;
		} finally {
			if (con != null) {
				con.getBcm().shutdown();
			}
		}
	}

	public void addUserToGroup(String token,HttpCon con,String userName,String groupName,int approvalID,Workflow workflow) throws Exception {
		Gson gson = new Gson();
		StringBuffer b = new StringBuffer();
		b.append("/oapi/v1/groups/").append(groupName);
		String json = this.callWS(token, con, b.toString());
		com.tremolosecurity.unison.openshiftv3.model.groups.Group group = gson.fromJson(json, com.tremolosecurity.unison.openshiftv3.model.groups.Group.class);
		if (group.getUsers() == null) {
			group.setUsers(new HashSet<String>());
		}
		if ( ! group.getUsers().contains(userName)) {
			
			group.getUsers().add(userName);
			json = gson.toJson(group);
			json = this.callWSPut(token, con, b.toString(), json);
			Response resp = gson.fromJson(json, Response.class);
			if (resp.getKind().equals("Group")) {
				this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Add,  approvalID, workflow, "group", groupName);
			} else {
				throw new Exception("Could not add group " + groupName + " to " + userName + " - " + resp.getReason());
			}
		}
	}
	
	public void removeUserFromGroup(String token,HttpCon con,String userName,String groupName,int approvalID,Workflow workflow) throws Exception {
		Gson gson = new Gson();
		StringBuffer b = new StringBuffer();
		b.append("/oapi/v1/groups/").append(groupName);
		String json = this.callWS(token, con, b.toString());
		com.tremolosecurity.unison.openshiftv3.model.groups.Group group = gson.fromJson(json, com.tremolosecurity.unison.openshiftv3.model.groups.Group.class);
		if (group.getUsers() == null) {
			group.setUsers(new HashSet<String>());
		}
		if (group.getUsers().contains(userName)) {
			
			group.getUsers().remove(userName);
			json = gson.toJson(group);
			json = this.callWSPut(token, con, b.toString(), json);
			Response resp = gson.fromJson(json, Response.class);
			if (resp.getKind().equals("Group")) {
				this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Delete,  approvalID, workflow, "group", groupName);
			} else {
				throw new Exception("Could not remove group " + groupName + " to " + userName + " - " + resp.getReason());
			}
		}
	}
}
