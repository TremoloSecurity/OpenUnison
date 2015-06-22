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
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URL;
import java.rmi.RemoteException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Map;
import java.util.Set;
import java.util.List;

import org.alfresco.webservice.accesscontrol.AccessControlFault;
import org.alfresco.webservice.accesscontrol.SiblingAuthorityFilter;
import org.alfresco.webservice.administration.AdministrationFault;
import org.alfresco.webservice.administration.NewUserDetails;
import org.alfresco.webservice.administration.UserDetails;
import org.alfresco.webservice.authentication.AuthenticationFault;
import org.alfresco.webservice.types.NamedValue;
import org.alfresco.webservice.util.AuthenticationUtils;
import org.alfresco.webservice.util.WebServiceFactory;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;

import com.google.gson.Gson;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.UserStoreProvider;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.provisioning.core.providers.util.AlfrescoGroup;
import com.tremolosecurity.provisioning.core.providers.util.AlfrescoUser;
import com.tremolosecurity.provisioning.core.providers.util.RootGroups;
import com.tremolosecurity.proxy.util.LastMileUtil;
import com.tremolosecurity.saml.Attribute;




public class AlfrescoProviderREST implements UserStoreProvider {
	
	String loginId;
	String loginPwd;
	String ticket;
	
	String endpoint;
	private String uidAttrName;
	
	boolean useLastMile;
	String lastMileKeyAlias;
	
	ConfigManager cfg;
	
	
	String name;
	
	public static final String HEADER_NAME = "X-Alfresco-Remote-User";
	private PoolingHttpClientConnectionManager phcm;
	private CloseableHttpClient httpclient;
	
	
	private String login() throws ClientProtocolException, IOException, ProvisioningException {
		StringBuffer b = new StringBuffer();
		b.append(this.endpoint).append("/login?u=").append(loginId).append("&pw=").append(loginPwd);
		
		HttpGet httpget = new HttpGet(b.toString());
		try {
			LastMileUtil.addLastMile(cfg, loginId, HEADER_NAME, httpget, lastMileKeyAlias, useLastMile);
		} catch (Exception e) {
			throw new ProvisioningException("Error generating provisioning last mile",e);
		}
		//httpget.addHeader("X-Alfresco-Remote-User", this.loginId);
		
		
		
		StringBuffer sb = new StringBuffer();
		String line = null;
		try {
			CloseableHttpResponse response = httpclient.execute(httpget);
			BufferedReader in = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
			while ((line = in.readLine()) != null) {
				sb.append(line).append('\n');
			}
			
			in.close();
			
			response.close();
			
		} finally {
			
			httpget.releaseConnection();
		}

		
		line = sb.toString();
		
		String token = line.substring(line.indexOf("<ticket>") + 8,line.indexOf("</ticket>"));
		
		
		
		return token;
	}

	@Override
	public void createUser(User user, Set<String> attributes,Map<String,Object> request)
			throws ProvisioningException {
		
		
		int approvalID = 0;
		
		
		
		
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		String token = "";
		
		try {
			token = this.login();
		} catch (Exception e) {
			throw new ProvisioningException("Could not initialize Alfresco Web Services Client",e);
		}
		
		AlfrescoUser newUser = new AlfrescoUser();
		AlfrescoUser createdUser = null;
		
		for (String attrName : user.getAttribs().keySet()) {
			Attribute attr = user.getAttribs().get(attrName);
			
			
			
			
			if (! attributes.contains(attr.getName())) {
				
				continue;
			}
			
			StringBuffer b = new StringBuffer();
			b.append("set").append(attrName.toUpperCase().charAt(0)).append(attrName.substring(1));
			String methodName = b.toString();
			
			try {
				Method method = AlfrescoUser.class.getMethod(methodName, String.class);
				method.invoke(newUser, attr.getValues().get(0));
			} catch (Exception e) {
				throw new ProvisioningException("Could not create user",e);
			}
			
		}
		
		newUser.setEnabled(true);
		
		
		Gson gson = new Gson();
		String json = gson.toJson(newUser, AlfrescoUser.class);
		
		
		
		StringBuffer b = new StringBuffer();
		b.append(this.endpoint).append("/people?alf_ticket=").append(token);
		HttpPost httppost = new HttpPost(b.toString());
		try {
			LastMileUtil.addLastMile(cfg, loginId, HEADER_NAME,httppost, lastMileKeyAlias, useLastMile);
		} catch (Exception e) {
			throw new ProvisioningException("Error generating provisioning last mile",e);
		}
		//httppost.addHeader("X-Alfresco-Remote-User", this.loginId);
		
		try {
			StringEntity data = new StringEntity(json);
			data.setContentType("application/json");
			httppost.setEntity(data);
			
			StringBuffer sb = new StringBuffer();
			String line = null;
			
			
			try {
				CloseableHttpResponse response = httpclient.execute(httppost);
				if (response.getStatusLine().getStatusCode() != 200) {
					
					response.close();
					httppost.releaseConnection();
					//
					throw new Exception("error");
				} else {
					BufferedReader in = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
					while ((line = in.readLine()) != null) {
						sb.append(line).append('\n');
					}
					in.close();
					createdUser = gson.fromJson(sb.toString(), AlfrescoUser.class);
				}
				
				
				response.close();
				
				
			this.cfg.getProvisioningEngine().logAction(this.name,true, ActionType.Add,  approvalID, workflow, "userName", createdUser.getUserName());
			} finally {
				
				httppost.releaseConnection();
			}
		} catch (Exception e) {
			
				//
			
			throw new ProvisioningException("Could not create user",e);
			
			
		}
		
		
		
		
		for (String attrName : user.getAttribs().keySet()) {
			Attribute attr = user.getAttribs().get(attrName);
			
			
			
			
			if (! attributes.contains(attr.getName())) {
				
				continue;
			}
			
			this.cfg.getProvisioningEngine().logAction(this.name,false, ActionType.Add, approvalID, workflow, attrName, user.getAttribs().get(attrName).getValues().get(0));
			
		}
		
		for (String group : user.getGroups()) {
			addUsertoGroup(token, createdUser.getUserName(), group,approvalID,workflow);
		}
		
		
			//
		
		

	}

	private void addUsertoGroup(String token, String createdUser, String group,int approvalID,Workflow workflow) throws ProvisioningException {
		HttpPost httppost;
		
		StringBuffer b = new StringBuffer(this.endpoint).append("/groups/").append(group).append("/children/").append(createdUser).append("?alf_ticket=").append(token);
		httppost = new HttpPost(b.toString());
		try {
			LastMileUtil.addLastMile(cfg, loginId,HEADER_NAME, httppost, lastMileKeyAlias, useLastMile);
		} catch (Exception e) {
			throw new ProvisioningException("Error generating provisioning last mile",e);
		}
		//httppost.addHeader("X-Alfresco-Remote-User", this.loginId);
		try {
			//StringEntity data = new StringEntity(json);
			//data.setContentType("application/json");
			//httpput.setEntity(data);
			
			try {
				CloseableHttpResponse response = httpclient.execute(httppost);
				if (response.getStatusLine().getStatusCode() != 200) {
					throw new Exception("error");
				} 
				response.close();
				
				
				this.cfg.getProvisioningEngine().logAction(this.name,false, ActionType.Add, approvalID, workflow, "group", group);
			} finally {
				
				httppost.releaseConnection();
			}
		} catch (Exception e) {
			throw new ProvisioningException("Could not create user",e);
		}
		
		
	}
	
	private void deleteUserFromGroup(String token, String createdUser,String group,int approvalID,Workflow workflow) throws ProvisioningException {
		HttpDelete httppost;
		StringBuffer b = new StringBuffer();
		b.append(this.endpoint).append("/groups/").append(group).append("/children/").append(createdUser).append("?alf_ticket=").append(token);
		httppost = new HttpDelete(b.toString());
		try {
			LastMileUtil.addLastMile(cfg, loginId,HEADER_NAME, httppost, lastMileKeyAlias, useLastMile);
		} catch (Exception e) {
			throw new ProvisioningException("Error generating provisioning last mile",e);
		}
		//httppost.addHeader("X-Alfresco-Remote-User", this.loginId);
		
		try {
			//StringEntity data = new StringEntity(json);
			//data.setContentType("application/json");
			//httpput.setEntity(data);
			
			try {
				CloseableHttpResponse response = httpclient.execute(httppost);
				if (response.getStatusLine().getStatusCode() != 200) {
					throw new Exception("error");
				} 
				
				response.close();
				
				this.cfg.getProvisioningEngine().logAction(this.name,false, ActionType.Delete, approvalID, workflow, "group", group);
			} finally {
				
				httppost.releaseConnection();
			}
		} catch (Exception e) {
			throw new ProvisioningException("Could not create user",e);
		}
		
		
	}

	@Override
	public void syncUser(User user, boolean addOnly, Set<String> attributes,Map<String,Object> request)
			throws ProvisioningException {
		
		
		int approvalID = 0;
		
		
		
		
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		String token = "";
		
		try {
			token = this.login();
		} catch (Exception e) {
			throw new ProvisioningException("Could not initialize Alfresco Web Services Client",e);
		}
		
		AlfrescoUser userDetails;
		try {
			userDetails = userLookup(user.getUserID(), token);
		} catch (Exception e) {
			this.createUser(user, attributes, request);
			return;
		}
		
		for (String attrName : user.getAttribs().keySet()) {
			Attribute attr = user.getAttribs().get(attrName);
			
			if (! attributes.contains(attr.getName())) {
				continue;
			}
			
			StringBuffer b = new StringBuffer();
			b.append("set").append(attrName.toUpperCase().charAt(0)).append(attrName.substring(1));
			String methodName = b.toString();
			
			try {
				Method method = AlfrescoUser.class.getMethod(methodName, String.class);
				method.invoke(userDetails, attr.getValues().get(0));
			} catch (Exception e) {
				throw new ProvisioningException("Could not create user",e);
			}
			
		}
		
		Gson gson = new Gson();
		String json = gson.toJson(userDetails, AlfrescoUser.class);
		
		
		StringBuffer b = new StringBuffer();
		b.append(this.endpoint).append("/people/").append(user.getUserID()).append("?alf_ticket=").append(token);
		
		HttpPut httpput = new HttpPut(b.toString());
		try {
			LastMileUtil.addLastMile(cfg, loginId,HEADER_NAME, httpput, lastMileKeyAlias, useLastMile);
		} catch (Exception e) {
			throw new ProvisioningException("Error generating provisioning last mile",e);
		}
		//httpput.addHeader("X-Alfresco-Remote-User", this.loginId);
		
		
		
		try {
			StringEntity data = new StringEntity(json);
			data.setContentType("application/json");
			httpput.setEntity(data);
			
			try {
			CloseableHttpResponse response = httpclient.execute(httpput);
			if (response.getStatusLine().getStatusCode() != 200) {
				throw new Exception("error");
			}
			
			response.close();
			} finally {
				
				httpput.releaseConnection();
			}
		} catch (Exception e) {
			throw new ProvisioningException("Could not sync user",e);
		}
		
		for (String attrName : user.getAttribs().keySet()) {
			Attribute attr = user.getAttribs().get(attrName);
			if (! attributes.contains(attr.getName())) {	
				continue;
			}
			
			this.cfg.getProvisioningEngine().logAction(this.name,false, ActionType.Replace, approvalID, workflow, attrName, user.getAttribs().get(attrName).getValues().get(0));
			
		}
		
		
		ArrayList<String> tmpgroups = new ArrayList<String>();
		tmpgroups.addAll(user.getGroups());
		List<String> groups = null;
		try {
			groups = this.groupUserGroups(user.getUserID(), token);
		} catch (Exception e1) {
			throw new ProvisioningException("Could not load groups",e1);
		}
		
		
		if (groups != null) {
			for (String group : groups) {
				
				
				if (tmpgroups.contains(group)) {
					tmpgroups.remove(group);
				} else {
					if (! addOnly) {
						this.deleteUserFromGroup(token, user.getUserID(), group,approvalID,workflow);
					}
				}
			}
			
			for (String group : tmpgroups) {
				this.addUsertoGroup(token, user.getUserID(),  group,approvalID,workflow);
			}
		}
		
		

	}

	@Override
	public void deleteUser(User user,Map<String,Object> request) throws ProvisioningException {
		String token = null;
		
		
		int approvalID = 0;
		
		
		
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		try {
			token = this.login();
		} catch (Exception e) {
			throw new ProvisioningException("Could not initialize Alfresco Web Services Client",e);
		}
		
		StringBuffer b = new StringBuffer();
		b.append(this.endpoint).append("/people/").append(user.getUserID()).append("?alf_ticket=").append(token);
		HttpDelete delete = new HttpDelete(b.toString());
		try {
			LastMileUtil.addLastMile(cfg, loginId, HEADER_NAME,delete, lastMileKeyAlias, useLastMile);
		} catch (Exception e) {
			throw new ProvisioningException("Error generating provisioning last mile",e);
		}
		//delete.addHeader("X-Alfresco-Remote-User", this.loginId);
		
		try {
			
			try {
				CloseableHttpResponse response = httpclient.execute(delete);
				if (response.getStatusLine().getStatusCode() != 200) {
					throw new Exception("Error Deleting user");
				}
				
				response.close();
				
				this.cfg.getProvisioningEngine().logAction(this.name,true, ActionType.Delete,approvalID, workflow, "userName", user.getUserID());
			} finally {
				
				delete.releaseConnection();
			}
		} catch (Exception e1) {
			throw new ProvisioningException("Could not delete user",e1);
		} 
		
		
		
			//
		
	}

	@Override
	public User findUser(String userID, Set<String> attributes,Map<String,Object> request) 
			throws ProvisioningException {
		String token = "";
		try {
			token = this.login();
		} catch (Exception e) {
			throw new ProvisioningException("Could not initialize Alfresco Web Services Client",e);
		}
		
		try {
			
			AlfrescoUser userDetails = userLookup(userID, token);
			
			
			
			Method[] methods = AlfrescoUser.class.getDeclaredMethods();
			
			User user = new User(userID);
			
			for (Method method : methods) {
				
				if (! method.getName().startsWith("get") || method.getParameterTypes().length > 0) {
					continue;
				}
				
				String val = null;
				
				if (method.getReturnType().equals(String.class)) {
					val = (String) method.invoke(userDetails);
				} else if (method.getReturnType().equals(Boolean.class)) {
					Boolean b = (Boolean) method.invoke(userDetails);
					val = b.toString();
				}
				
				String name = method.getName().substring(3 + 1);
				StringBuffer b = new StringBuffer();
				b.append(method.getName().toLowerCase().charAt(3)).append(name);
				name = b.toString();
				
				if (attributes.size() > 0 && ! attributes.contains(name)) {
					continue;
				}
				
				if (val != null && ! val.isEmpty()) {
					Attribute userAttr = new Attribute(name,val);
					user.getAttribs().put(name, userAttr);
				}
				
			}
			
			List<String> groups = this.groupUserGroups(userID, token);
			for (String group : groups) {
				
				user.getGroups().add(group);
			}
			

			
			return user;
		} catch (Exception e) {
			StringBuffer b = new StringBuffer();
			b.append("Could not retrieve user ").append(userID);
			throw new ProvisioningException(b.toString() ,e);
		} 
	}

	private AlfrescoUser userLookup(String userID, String token)
			throws IOException, ClientProtocolException, ProvisioningException {
		
		StringBuffer b = new StringBuffer();
		b.append(this.endpoint).append("/people/").append(userID).append("?alf_ticket=").append(token);
		HttpGet httpget = new HttpGet(b.toString());
		
		try {
			
			
			try {
				LastMileUtil.addLastMile(cfg, loginId,HEADER_NAME, httpget, lastMileKeyAlias, useLastMile);
			} catch (Exception e) {
				throw new ProvisioningException("Error generating provisioning last mile",e);
			}
			//httpget.addHeader("X-Alfresco-Remote-User", this.loginId);
			
			CloseableHttpResponse response = httpclient.execute(httpget);
			
			if (response.getStatusLine().getStatusCode() == 404) {
				throw new ProvisioningException("User does not exist");
			}
			
			BufferedReader in = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
			StringBuffer sb = new StringBuffer();
			String line = null;
			while ((line = in.readLine()) != null) {
				sb.append(line).append('\n');
			}
			
			in.close();
			response.close();
			
			line = sb.toString();
			
			int index = line.indexOf("\"capabilities\"");
			index = line.lastIndexOf(',', index);
			b.setLength(0);
			b.append(line.substring(0,index)).append("\n}");
			line = b.toString();
			
			
			
			Gson gson = new Gson();
			AlfrescoUser userDetails = gson.fromJson(line, AlfrescoUser.class);
			return userDetails;
		} finally {
			httpget.releaseConnection();
			
			
		}
	}

	private List<String> groupUserGroups(String userID,String token) throws Exception {
		StringBuffer b = new StringBuffer();
		b.append(this.endpoint).append("/rootgroups?alf_ticket=").append(token);
		HttpGet httpget = new HttpGet(b.toString());
		try {
			LastMileUtil.addLastMile(cfg, loginId,HEADER_NAME, httpget, lastMileKeyAlias, useLastMile);
		} catch (Exception e) {
			throw new ProvisioningException("Error generating provisioning last mile",e);
		}
		//httpget.addHeader("X-Alfresco-Remote-User", this.loginId);
		
		StringBuffer sb = new StringBuffer();
		String line = null;
		try {
			CloseableHttpResponse response = httpclient.execute(httpget);
			BufferedReader in = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
			
			while ((line = in.readLine()) != null) {
				sb.append(line).append('\n');
			}
			
			in.close();
			response.close();
			
		} finally {
			httpget.releaseConnection();
			
		}
		
		line = sb.toString();
		
		Gson gson = new Gson();
		RootGroups root = gson.fromJson(line, RootGroups.class);
		ArrayList<String> groups = new ArrayList<String>();
		
		for (AlfrescoGroup group : root.getData()) {
			this.addGroupChildren(userID, group.getShortName(), token, groups);
		}
		
		return groups;
	}
	
	private void addGroupChildren(String userID,String groupShortName,String token,List<String> groups) throws Exception {
		StringBuffer b = new StringBuffer();
		b.append(this.endpoint).append("/groups/").append(groupShortName).append("/children?alf_ticket=").append(token);
		HttpGet httpget = new HttpGet(b.toString());
		try {
			LastMileUtil.addLastMile(cfg, loginId, HEADER_NAME,httpget, lastMileKeyAlias, useLastMile);
		} catch (Exception e) {
			throw new ProvisioningException("Error generating provisioning last mile",e);
		}
		//httpget.addHeader("X-Alfresco-Remote-User", this.loginId);
		StringBuffer sb = new StringBuffer();
		String line = null;
		
		try {
			CloseableHttpResponse response = httpclient.execute(httpget);
			BufferedReader in = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
			while ((line = in.readLine()) != null) {
				sb.append(line).append('\n');
			}
			
			in.close();
			response.close();
			
		} finally {
			httpget.releaseConnection();
			
		}
		
		line = sb.toString();
		
		Gson gson = new Gson();
		RootGroups root = gson.fromJson(line, RootGroups.class);
		
		for (AlfrescoGroup group : root.getData()) {
			if (group.getAuthorityType().equalsIgnoreCase("USER")) {
				if (group.getShortName().equalsIgnoreCase(userID)) {
					groups.add(groupShortName);
				}
			} else if (group.getAuthorityType().equalsIgnoreCase("GROUP")) {
				this.addGroupChildren(userID, group.getShortName(), token, groups);
			}
		}
	}
	
	@Override
	public void init(Map<String, Attribute> cfg,ConfigManager cfgMgr,String name)
			throws ProvisioningException {
		
		this.name = name;
		
		this.loginId = cfg.get("adminUser").getValues().get(0);
		this.loginPwd = cfg.get("adminPwd").getValues().get(0);
		this.endpoint = cfg.get("url").getValues().get(0);
		this.uidAttrName = cfg.get("uidAttributeName").getValues().get(0);
		this.useLastMile = Boolean.parseBoolean(cfg.get("useLastMile").getValues().get(0));
		this.lastMileKeyAlias = cfg.get("lastMileKeyAlias").getValues().get(0);
		
		this.cfg = cfgMgr;
		
		phcm = new PoolingHttpClientConnectionManager(cfgMgr.getHttpClientSocketRegistry());
		httpclient = HttpClients.custom().setConnectionManager(phcm).build();
		
		
		
		
		WebServiceFactory.setEndpointAddress(this.endpoint);
		
		
		
	}

	@Override
	public void setUserPassword(User user,Map<String,Object> request) throws ProvisioningException {
				
	}

}
