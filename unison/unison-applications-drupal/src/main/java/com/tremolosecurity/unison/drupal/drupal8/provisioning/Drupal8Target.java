/*******************************************************************************
 * Copyright 2019 Tremolo Security, Inc.
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
package com.tremolosecurity.unison.drupal.drupal8.provisioning;

import java.beans.PropertyVetoException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import javax.sql.DataSource;

import org.apache.http.Header;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.message.BasicHeader;
import org.apache.http.util.EntityUtils;
import org.apache.logging.log4j.Logger;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.mchange.v2.c3p0.ComboPooledDataSource;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.UserStoreProvider;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.saml.Attribute.DataType;
import com.tremolosecurity.server.StopableThread;

import net.sourceforge.myvd.inserts.jdbc.JdbcInsert;

public class Drupal8Target implements UserStoreProvider {
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(Drupal8Target.class.getName());
	
	String url;
	String user;
	String password;
	
	
	
	
	String name;
	
	
	private ConfigManager cfgMgr;
	
	static HashSet<String> defaultAttributes;
	
	static {
		defaultAttributes = new HashSet<String>();
		defaultAttributes.add("name");
		defaultAttributes.add("langcode");
		defaultAttributes.add("preferred_langcode");
		defaultAttributes.add("preferred_admin_langcode");
		defaultAttributes.add("preferred_admin_langcode");
		defaultAttributes.add("mail");
		defaultAttributes.add("status");
		
		
		
	}
	

	@Override
	public void createUser(User user, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		
		int userID = 0;
		int approvalID = 0;
		int workflowID = 0;
		
		if (request.containsKey("TREMOLO_USER_ID")) {
			userID = (Integer) request.get("TREMOLO_USER_ID");
		}
		
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		if (request.containsKey("WORKFLOW_ID")) {
			workflowID = (Integer) request.get("WORKFLOW_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		StringBuilder sb = new StringBuilder();
		JSONObject root = new JSONObject();
		
		HashMap<String,String> attrsForAudit = new HashMap<String,String>();
		
		if (attributes.contains("name") && user.getAttribs().containsKey("name")) {
			this.setJsonValue("name", user.getAttribs().get("name").getValues().get(0), root);
			attrsForAudit.put("name", user.getAttribs().get("name").getValues().get(0));
		}
		
		if (attributes.contains("langcode") && user.getAttribs().containsKey("langcode")) {
			this.setJsonValue("langcode", user.getAttribs().get("langcode").getValues().get(0), root);
			attrsForAudit.put("langcode", user.getAttribs().get("langcode").getValues().get(0));
		}
		
		if (attributes.contains("preferred_langcode") && user.getAttribs().containsKey("preferred_langcode")) {
			this.setJsonValue("preferred_langcode", user.getAttribs().get("preferred_langcode").getValues().get(0), root);
			attrsForAudit.put("preferred_langcode", user.getAttribs().get("preferred_langcode").getValues().get(0));
		}
		
		if (attributes.contains("preferred_admin_langcode") && user.getAttribs().containsKey("preferred_admin_langcode")) {
			this.setJsonValue("preferred_admin_langcode", user.getAttribs().get("preferred_admin_langcode").getValues().get(0), root);
			attrsForAudit.put("preferred_admin_langcode", user.getAttribs().get("preferred_admin_langcode").getValues().get(0));
		}
		
		if (attributes.contains("mail") && user.getAttribs().containsKey("mail")) {
			this.setJsonValue("mail", user.getAttribs().get("mail").getValues().get(0), root);
			attrsForAudit.put("mail", user.getAttribs().get("mail").getValues().get(0));
		}
		
		if (attributes.contains("status") && user.getAttribs().containsKey("status")) {
			this.setJsonValueBoolean("status", user.getAttribs().get("status").getValues().get(0), root);
			attrsForAudit.put("status", user.getAttribs().get("status").getValues().get(0));
		}
		
		for (String userAttributeName : user.getAttribs().keySet()) {
			if (attributes.contains(userAttributeName) && ! defaultAttributes.contains(userAttributeName)) {
				this.setJsonValue("field_" + userAttributeName , user.getAttribs().get(userAttributeName).getValues().get(0), root);
				attrsForAudit.put("field_" + userAttributeName, user.getAttribs().get(userAttributeName).getValues().get(0));
			}
		}
		
		
		
		JSONArray roles = new JSONArray();
		
		for (String groupName : user.getGroups()) {
			JSONObject group = new JSONObject();
			group.put("target_id", groupName);
			roles.add(group);
		}
		
		root.put("roles", roles);
		
		HttpPost post = new HttpPost(this.url + "/entity/user?_format=json");
		post.setHeader(new BasicHeader("X-CSRF-Token",UUID.randomUUID().toString()));
		post.addHeader("Content-Type", "application/json");
		try {
			post.setEntity(new StringEntity(root.toJSONString()));
		} catch (UnsupportedEncodingException e) {
			throw new ProvisioningException("Couldn't create user",e);
		}
		
		
		sb.setLength(0);
		sb.append(this.user).append(":").append(this.password);
		String azHeader = java.util.Base64.getEncoder().encodeToString(sb.toString().getBytes());
		sb.setLength(0);
		post.setHeader("Authorization", sb.append("Basic ").append(azHeader).toString());
		
		HttpCon con = null;
		try {
			con  = this.createClient();
		} catch (Exception e) {
			throw new ProvisioningException("Couldn't create user",e);
		}
		
		try {
			CloseableHttpResponse resp = con.getHttp().execute(post);
			if (resp.getStatusLine().getStatusCode() == 201) {
				String json = EntityUtils.toString(resp.getEntity());
				
				JSONParser parser = new JSONParser();
				root = (JSONObject) parser.parse(json);
				
				String uid = getJsonValue("uid",root);
				
				this.cfgMgr.getProvisioningEngine().logAction(this.name,true, ActionType.Add, approvalID, workflow, "uid", uid);
				
				for (String attr : attrsForAudit.keySet()) {
					this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Add, approvalID, workflow, attr, attrsForAudit.get(attr));
				}
				
				for (String groupName : user.getGroups()) {
					this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Add, approvalID, workflow, "role", groupName);
				}
				
				user.setUserID(uid);
				
			} else {
				throw new ProvisioningException("Could not create user with code " + resp.getStatusLine().getStatusCode());
			}
		} catch (IOException | ParseException e) {
			throw new ProvisioningException("Couldn't create user",e);
		}
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		

	}

	@Override
	public void setUserPassword(User user, Map<String, Object> request) throws ProvisioningException {
		// TODO Auto-generated method stub

	}

	private boolean syncAttribute(String name,User user,User fromDrupal,Set<String> attributes) {
		return attributes.contains(name) && user.getAttribs().containsKey(name) && ! user.getAttribs().get(name).getValues().get(0).equalsIgnoreCase(fromDrupal.getAttribs().get(name).getValues().get(0));
	}
	
	@Override
	public void syncUser(User user, boolean addOnly, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		if (user.getUserID().isEmpty()) {
			this.createUser(user, attributes, request);
			return;
		}
		
		int userID = 0;
		int approvalID = 0;
		int workflowID = 0;
		
		if (request.containsKey("TREMOLO_USER_ID")) {
			userID = (Integer) request.get("TREMOLO_USER_ID");
		}
		
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		if (request.containsKey("WORKFLOW_ID")) {
			workflowID = (Integer) request.get("WORKFLOW_ID");
		}
		
		
		User fromDrupal = this.findUser(user.getUserID(), attributes, request);
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		StringBuilder sb = new StringBuilder();
		JSONObject root = new JSONObject();
		
		HashMap<String,String> attrsForAudit = new HashMap<String,String>();
		
		if (syncAttribute("name",user,fromDrupal,attributes)) {
			this.setJsonValue("name", user.getAttribs().get("name").getValues().get(0), root);
			attrsForAudit.put("name", user.getAttribs().get("name").getValues().get(0));
		}
		
		if (syncAttribute("langcode",user,fromDrupal,attributes)) {
			this.setJsonValue("langcode", user.getAttribs().get("langcode").getValues().get(0), root);
			attrsForAudit.put("langcode", user.getAttribs().get("langcode").getValues().get(0));
		}
		
		if (syncAttribute("preferred_langcode",user,fromDrupal,attributes)) {
			this.setJsonValue("preferred_langcode", user.getAttribs().get("preferred_langcode").getValues().get(0), root);
			attrsForAudit.put("preferred_langcode", user.getAttribs().get("preferred_langcode").getValues().get(0));
		}
		
		if (syncAttribute("preferred_admin_langcode",user,fromDrupal,attributes)) {
			this.setJsonValue("preferred_admin_langcode", user.getAttribs().get("preferred_admin_langcode").getValues().get(0), root);
			attrsForAudit.put("preferred_admin_langcode", user.getAttribs().get("preferred_admin_langcode").getValues().get(0));
		}
		
		if (syncAttribute("mail",user,fromDrupal,attributes)) {
			this.setJsonValue("mail", user.getAttribs().get("mail").getValues().get(0), root);
			attrsForAudit.put("mail", user.getAttribs().get("mail").getValues().get(0));
		}
		
		if (syncAttribute("status",user,fromDrupal,attributes)) {
			this.setJsonValueBoolean("status", user.getAttribs().get("status").getValues().get(0), root);
			attrsForAudit.put("status", user.getAttribs().get("status").getValues().get(0));
		}
		
		
		for (String userAttributeName : user.getAttribs().keySet()) {
			if (! defaultAttributes.contains(userAttributeName) && this.syncAttribute(userAttributeName, user, fromDrupal, attributes)) {
				this.setJsonValue("field_" + userAttributeName , user.getAttribs().get(userAttributeName).getValues().get(0), root);
				attrsForAudit.put("field_" + userAttributeName, user.getAttribs().get(userAttributeName).getValues().get(0));
			}
		}
		
		
		
		JSONArray roles = new JSONArray();
		
		List<String> addedRoles = new ArrayList<String>();
		List<String> removedRoles = new ArrayList<String>();
		
		for (String groupName : user.getGroups()) {
			
			
			if (! fromDrupal.getGroups().contains(groupName)) {
				addedRoles.add(groupName);
			}
			
			
			
			JSONObject group = new JSONObject();
			group.put("target_id", groupName);
			roles.add(group);
		}
		
		for (String groupName : fromDrupal.getGroups()) {
			if (! user.getGroups().contains(groupName)) {
				if (addOnly) {
					JSONObject group = new JSONObject();
					group.put("target_id", groupName);
					roles.add(group);
				} else {
					removedRoles.add(groupName);	
				}
			}
		}
		
		root.put("roles", roles);
		
		
		HttpPatch post = new HttpPatch(this.url + "/user/" + user.getUserID() + "?_format=json");
		post.setHeader(new BasicHeader("X-CSRF-Token",UUID.randomUUID().toString()));
		post.addHeader("Content-Type", "application/json");
		try {
			post.setEntity(new StringEntity(root.toJSONString()));
		} catch (UnsupportedEncodingException e) {
			throw new ProvisioningException("Couldn't create user",e);
		}
		
		
		sb.setLength(0);
		sb.append(this.user).append(":").append(this.password);
		String azHeader = java.util.Base64.getEncoder().encodeToString(sb.toString().getBytes());
		sb.setLength(0);
		post.setHeader("Authorization", sb.append("Basic ").append(azHeader).toString());
		
		HttpCon con = null;
		try {
			con  = this.createClient();
		} catch (Exception e) {
			throw new ProvisioningException("Couldn't create user",e);
		}
		
		try {
			CloseableHttpResponse resp = con.getHttp().execute(post);
			if (resp.getStatusLine().getStatusCode() == 200) {
				String json = EntityUtils.toString(resp.getEntity());
				
				JSONParser parser = new JSONParser();
				root = (JSONObject) parser.parse(json);
				
				String uid = getJsonValue("uid",root);
				
				
				
				for (String attr : attrsForAudit.keySet()) {
					this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Replace, approvalID, workflow, attr, attrsForAudit.get(attr));
				}
				
				for (String groupName : addedRoles) {
					this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Add, approvalID, workflow, "role", groupName);
				}
				
				for (String groupName : removedRoles) {
					this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Delete, approvalID, workflow, "role", groupName);
				}
				
				user.setUserID(uid);
				
			} else {
				throw new ProvisioningException("Could not create user with code " + resp.getStatusLine().getStatusCode());
			}
		} catch (IOException | ParseException e) {
			throw new ProvisioningException("Couldn't create user",e);
		}

	}

	@Override
	public void deleteUser(User user, Map<String, Object> request) throws ProvisioningException {
		
		int userID = 0;
		int approvalID = 0;
		int workflowID = 0;
		
		if (request.containsKey("TREMOLO_USER_ID")) {
			userID = (Integer) request.get("TREMOLO_USER_ID");
		}
		
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		if (request.containsKey("WORKFLOW_ID")) {
			workflowID = (Integer) request.get("WORKFLOW_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		StringBuilder sb = new StringBuilder();
		sb.append(url).append("/user/").append(user.getUserID()).append("?_format=json");
		
		HttpCon con = null;
		
		try {
			con = this.createClient();
			
			HttpDelete req = new HttpDelete(sb.toString());
			sb.setLength(0);
			sb.append(this.user).append(":").append(this.password);
			String azHeader = java.util.Base64.getEncoder().encodeToString(sb.toString().getBytes());
			sb.setLength(0);
			req.setHeader("Authorization", sb.append("Basic ").append(azHeader).toString());
			CloseableHttpResponse resp = con.getHttp().execute(req);
			
			if (resp.getStatusLine().getStatusCode() != 204) {
				logger.warn("User '" + user.getUserID() + "' not found" );
				return;
			}
			
			this.cfgMgr.getProvisioningEngine().logAction(this.name,true, ActionType.Delete, approvalID, workflow, "uid", user.getUserID());
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not find user",e);
		} finally {
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

		StringBuilder sb = new StringBuilder();
		sb.append(url).append("/user/").append(userID).append("?_format=json");
		
		HttpCon con = null;
		
		try {
			con = this.createClient();
			
			HttpGet req = new HttpGet(sb.toString());
			sb.setLength(0);
			sb.append(this.user).append(":").append(this.password);
			String azHeader = java.util.Base64.getEncoder().encodeToString(sb.toString().getBytes());
			sb.setLength(0);
			req.setHeader("Authorization", sb.append("Basic ").append(azHeader).toString());
			CloseableHttpResponse resp = con.getHttp().execute(req);
			
			if (resp.getStatusLine().getStatusCode() != 200) {
				logger.warn("User '" + userID + "' not found" );
				return null;
			}
			
			String json = EntityUtils.toString(resp.getEntity());
			
			JSONParser parser = new JSONParser();
			JSONObject root = (JSONObject) parser.parse(json);
			
			String uid = getJsonValue("uid",root);
			
			User user = new User(uid);
			
			if (attributes.contains("uuid")) {
				String uuid = getJsonValue("uuid",root);
				user.getAttribs().put("uuid",new Attribute("uuid",uuid));
			}
			
			
			if (attributes.contains("name")) {
				String uuid = getJsonValue("name",root);
				user.getAttribs().put("name",new Attribute("name",uuid));
			}
			
			if (attributes.contains("langcode")) {
				String uuid = getJsonValue("langcode",root);
				user.getAttribs().put("langcode",new Attribute("langcode",uuid));
			}
			
			if (attributes.contains("preferred_langcode")) {
				String uuid = getJsonValue("preferred_langcode",root);
				user.getAttribs().put("preferred_langcode",new Attribute("preferred_langcode",uuid));
			}
			
			if (attributes.contains("preferred_admin_langcode")) {
				String uuid = getJsonValue("preferred_admin_langcode",root);
				user.getAttribs().put("preferred_admin_langcode",new Attribute("preferred_admin_langcode",uuid));
			}
			
			if (attributes.contains("mail")) {
				String uuid = getJsonValue("mail",root);
				user.getAttribs().put("mail",new Attribute("mail",uuid));
			}
			
			if (attributes.contains("status")) {
				String uuid = getJsonValue("status",root);
				user.getAttribs().put("status",new Attribute("status",uuid));
				user.getAttribs().get("status").setDataType(DataType.booleanVal);
			}
			
			if (attributes.contains("created")) {
				String uuid = getJsonValue("created",root);
				user.getAttribs().put("created",new Attribute("created",uuid));
			}
			
			if (attributes.contains("changed")) {
				String uuid = getJsonValue("changed",root);
				user.getAttribs().put("changed",new Attribute("changed",uuid));
			}
			
			if (attributes.contains("access")) {
				String uuid = getJsonValue("access",root);
				user.getAttribs().put("access",new Attribute("access",uuid));
			}
			
			if (attributes.contains("default_langcode")) {
				String uuid = getJsonValue("default_langcode",root);
				user.getAttribs().put("default_langcode",new Attribute("default_langcode",uuid));
				user.getAttribs().get("default_langcode").setDataType(DataType.booleanVal);
			}
			
			JSONArray roles = (JSONArray) root.get("roles");
			for (Object o : roles) {
				JSONObject role = (JSONObject) o;
				user.getGroups().add((String) role.get("target_id"));
			}
			
			for (Object o : root.keySet()) {
				String keyName = (String) o;
				if (keyName.startsWith("field_")) {
					String attributeName = keyName.substring(6);
					if (attributes.contains(attributeName)) {
						user.getAttribs().put(attributeName, new Attribute(attributeName,this.getJsonValue(keyName, root)));
					}
				}
			}
			
			return user;
			
			
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not find user",e);
		} finally {
			if (con != null) {
				try {
					con.getHttp().close();
				} catch (IOException e) {
					
				}
				
				con.getBcm().close();
			}
		}
		
		
	}
	
	private String getJsonValue(String name,JSONObject root) {
		JSONArray val = (JSONArray) root.get(name);
		JSONObject obj = (JSONObject) val.get(0);
		return  obj.get("value").toString();
	}
	
	private void setJsonValue(String name, String value,JSONObject root) {
		JSONArray array = new JSONArray();
		JSONObject val = new JSONObject();
		val.put("value", value);
		array.add(val);
		root.put(name, array);
	}
	
	private void setJsonValueBoolean(String name, String value,JSONObject root) {
		JSONArray array = new JSONArray();
		JSONObject val = new JSONObject();
		val.put("value", value.equalsIgnoreCase("true"));
		array.add(val);
		root.put(name, array);
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

	@Override
	public void init(Map<String, Attribute> cfg, ConfigManager cfgMgr, String name) throws ProvisioningException {
		this.name = name;
		this.url = cfg.get("url").getValues().get(0);
		this.user = cfg.get("user").getValues().get(0);
		this.password = cfg.get("password").getValues().get(0);
		
		this.cfgMgr = cfgMgr;
		
		

	}

	@Override
	public void shutdown() throws ProvisioningException {

		
	}
	
	

}
