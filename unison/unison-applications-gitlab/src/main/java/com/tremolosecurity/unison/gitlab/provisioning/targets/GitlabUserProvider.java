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
package com.tremolosecurity.unison.gitlab.provisioning.targets;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.beanutils.BeanUtils;
import org.apache.http.Header;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.message.BasicHeader;
import org.apache.http.util.EntityUtils;
import org.apache.logging.log4j.Logger;
import org.gitlab4j.api.GitLabApi;
import org.gitlab4j.api.GitLabApiException;
import org.gitlab4j.api.GroupApi;
import org.gitlab4j.api.UserApi;
import org.gitlab4j.api.models.AccessLevel;
import org.gitlab4j.api.models.Group;
import org.gitlab4j.api.models.Identity;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.UserStoreProviderWithAddGroup;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.util.GenPasswd;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;

import com.tremolosecurity.saml.Attribute;

public class GitlabUserProvider implements UserStoreProviderWithAddGroup {
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(GitlabUserProvider.class.getName());
	
	ConfigManager cfgMgr;
	
	String name;
    String token;

    String url;
    
    GitLabApi gitLabApi;
    UserApi userApi;
    GroupApi groupApi;
    
    BeanUtils beanUtils = new BeanUtils();
    
    public static final String GITLAB_IDENTITIES = "com.tremolosecurity.unison.gitlab.itentities";
    public static final String GITLAB_GROUP_ENTITLEMENTS = "com.tremolosecurity.unison.gitlab.group-entitlements";
	@Override
	public void createUser(User user, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		org.gitlab4j.api.models.User newUser = new org.gitlab4j.api.models.User();
		newUser.setUsername(user.getUserID());
		
		for (String attrName : attributes) {
			Attribute attr = user.getAttribs().get(attrName);
			if (attr != null) {
				try {
					this.beanUtils.setProperty(newUser, attrName, attr.getValues().get(0));
				} catch (IllegalAccessException | InvocationTargetException e) {
					throw new ProvisioningException("Could not set " + attrName + " for " + user.getUserID(),e);
				}
			}
		}
		
		
		
		try {
			this.userApi.createUser(newUser, new GenPasswd(50).getPassword(), false);
		} catch (GitLabApiException e) {
			throw new ProvisioningException("Could not create user",e);
		}
		
		newUser = this.findUserByName(user.getUserID());
		
		int numTries = 0;
		
		while (newUser == null) {
			if (numTries > 10) {
				throw new ProvisioningException("User " + user.getUserID() + " never created");
			}
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
			}
			
			newUser = this.findUserByName(user.getUserID());
			numTries++;
			
		}
		
		this.cfgMgr.getProvisioningEngine().logAction(this.name,true, ActionType.Add,  approvalID, workflow, "id", newUser.getId().toString());
		
		for (String attrName : attributes) {
			Attribute attr = user.getAttribs().get(attrName);
			if (attr != null) {
				this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Add,  approvalID, workflow, attrName, attr.getValues().get(0));
			}
		}
		
		
		
		List<GitlabFedIdentity> ids = (List<GitlabFedIdentity>) request.get(GitlabUserProvider.GITLAB_IDENTITIES);
		
		if (ids != null) {
			
			ArrayList<Header> defheaders = new ArrayList<Header>();
			defheaders.add(new BasicHeader("Private-Token", this.token));

			BasicHttpClientConnectionManager bhcm = new BasicHttpClientConnectionManager(
					cfgMgr.getHttpClientSocketRegistry());

			RequestConfig rc = RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD).setRedirectsEnabled(false)
					.build();

			CloseableHttpClient http = HttpClients.custom()
					                  .setConnectionManager(bhcm)
					                  .setDefaultHeaders(defheaders)
					                  .setDefaultRequestConfig(rc)
					                  .build();
			
			try {
			
				for (GitlabFedIdentity id : ids) {
					HttpPut getmembers = new HttpPut(new StringBuilder().append(this.url).append("/api/v4/users/").append(newUser.getId()).append("?provider=").append(id.getProvider()).append("&extern_uid=").append(URLEncoder.encode(user.getUserID(), "UTF-8")).toString());
					CloseableHttpResponse resp = http.execute(getmembers);
					
					if (resp.getStatusLine().getStatusCode() != 200) {
						throw new IOException("Invalid response " + resp.getStatusLine().getStatusCode());
					}
					
					this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Add,  approvalID, workflow, "identity-provider", id.getProvider());
					this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Add,  approvalID, workflow, "identity-externid", id.getExternalUid());
					
				}
			
			} catch (IOException  e) {
				throw new ProvisioningException("Could not set identity",e);
			} finally {
				try {
					http.close();
				} catch (IOException e) {
					
				}
				
				bhcm.close();
				
			}
			
			
		}
		
		HashMap<String,Integer> groupmap = (HashMap<String, Integer>) request.get(GitlabUserProvider.GITLAB_GROUP_ENTITLEMENTS);
		if (groupmap == null) {
			groupmap = new HashMap<String, Integer>();
		}
		for (String group : user.getGroups()) {
			try {
				Group groupObj = this.findGroupByName(group);
				if (groupObj == null) {
					logger.warn("Group " + group + " does not exist");
				} else {
					int accessLevel = AccessLevel.DEVELOPER.ordinal();
					if (groupmap.containsKey(group)) {
						accessLevel = groupmap.get(group);
					}
					this.groupApi.addMember(groupObj.getId(), newUser.getId(), accessLevel);
					this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Add,  approvalID, workflow, "group", group);
				}
			} catch (GitLabApiException e) {
				throw new ProvisioningException("Could not find group " + group,e);
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
		List<GitlabFedIdentity> ids = (List<GitlabFedIdentity>) request.get(GitlabUserProvider.GITLAB_IDENTITIES);
		
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		User fromGitlab = this.findUser(user.getUserID(), attributes, request);
		
		if (fromGitlab == null) {
			this.createUser(user, attributes, request);
			return;
		}
		
		List<GitlabFedIdentity> idsFromGitlab = (List<GitlabFedIdentity>) request.get(GitlabUserProvider.GITLAB_IDENTITIES);
		
		HashMap<String,String> toSet = new HashMap<String,String>();
		HashSet<String> toDelete = new HashSet<String>();
		for (String attrName : attributes) {
			Attribute attrFromGitlab = fromGitlab.getAttribs().get(attrName);
			Attribute attrIn = user.getAttribs().get(attrName);
			
			if ((attrIn != null && attrFromGitlab == null) || (attrIn != null && attrFromGitlab != null && ! attrIn.getValues().get(0).equals(attrFromGitlab.getValues().get(0)))) {
				toSet.put(attrName,attrIn.getValues().get(0));
			} else if (! addOnly) {
				if (attrIn == null && attrFromGitlab != null) {
					toDelete.add(attrName);
				}
			}
		}
		
		org.gitlab4j.api.models.User toSave = this.findUserByName(user.getUserID());
		
		for (String attrName : toSet.keySet()) {
			try {
				this.beanUtils.setProperty(toSave, attrName, toSet.get(attrName));
			} catch (IllegalAccessException | InvocationTargetException e) {
				throw new ProvisioningException("Could not update user " + user.getUserID(),e);
			}
		}
		
		for (String attrName : toDelete) {
			try {
				this.beanUtils.setProperty(toSave, attrName, "");
			} catch (IllegalAccessException | InvocationTargetException e) {
				throw new ProvisioningException("Could not update user " + user.getUserID(),e);
			}
		}
		
		
		
		
		
		
		
		
		
		
		if (ids != null) {
			
			ArrayList<Header> defheaders = new ArrayList<Header>();
			defheaders.add(new BasicHeader("Private-Token", this.token));

			BasicHttpClientConnectionManager bhcm = new BasicHttpClientConnectionManager(
					cfgMgr.getHttpClientSocketRegistry());

			RequestConfig rc = RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD).setRedirectsEnabled(false)
					.build();

			CloseableHttpClient http = HttpClients.custom()
					                  .setConnectionManager(bhcm)
					                  .setDefaultHeaders(defheaders)
					                  .setDefaultRequestConfig(rc)
					                  .build();
			
			try {
			
				for (GitlabFedIdentity id : ids) {
					
					boolean found = false;
					
					for (GitlabFedIdentity idfromgl : idsFromGitlab) {
						if (id.getExternalUid().equals(idfromgl.getExternalUid()) && id.getProvider().equals(idfromgl.getProvider()) ) {
							found = true;
							break;
						}
					}
					
					if (! found) {
					
						HttpPut getmembers = new HttpPut(new StringBuilder().append(this.url).append("/api/v4/users/").append(toSave.getId()).append("?provider=").append(id.getProvider()).append("&extern_uid=").append(URLEncoder.encode(user.getUserID(), "UTF-8")).toString());
						CloseableHttpResponse resp = http.execute(getmembers);
						
						if (resp.getStatusLine().getStatusCode() != 200) {
							throw new IOException("Invalid response " + resp.getStatusLine().getStatusCode());
						}
						
						this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Add,  approvalID, workflow, "identity-provider", id.getProvider());
						this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Add,  approvalID, workflow, "identity-externid", id.getExternalUid());
					}
					
				}
			
			} catch (IOException  e) {
				throw new ProvisioningException("Could not set identity",e);
			} finally {
				try {
					http.close();
				} catch (IOException e) {
					
				}
				
				bhcm.close();
				
			}
			
			
		}
		
		try {
			this.userApi.updateUser(toSave, null);
		} catch (GitLabApiException e) {
			throw new ProvisioningException("Could not save user " + user.getUserID(),e);
		}
		
		for (String attrName : toSet.keySet()) {
			this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Replace,  approvalID, workflow, attrName, toSet.get(attrName));
		}
		
		for (String attrName : toDelete) {
			this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Replace,  approvalID, workflow, attrName, "");
		}
		
		HashMap<String,Integer> groupmap = (HashMap<String, Integer>) request.get(GitlabUserProvider.GITLAB_GROUP_ENTITLEMENTS);
		if (groupmap == null) {
			groupmap = new HashMap<String, Integer>();
		}
		
		for (String inGroup : user.getGroups()) {
			if (! fromGitlab.getGroups().contains(inGroup)) {
				try {
					Group groupObj = this.findGroupByName(inGroup);
					if (groupObj == null) {
						logger.warn("Group " + inGroup + " does not exist");
					} else {
						int accessLevel = AccessLevel.DEVELOPER.ordinal();
						if (groupmap.containsKey(inGroup)) {
							accessLevel = groupmap.get(inGroup);
						}
						
						this.groupApi.addMember(groupObj.getId(), toSave.getId(), accessLevel);
						this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Add,  approvalID, workflow, "group", inGroup);
					}
				} catch (GitLabApiException e) {
					if (e.getMessage().equalsIgnoreCase("Member already exists")) {
						continue;
					} else {
						throw new ProvisioningException("Could not find group " + inGroup,e);
					}
				}
			}
		}
		
		if (! addOnly) {
			for (String groupFromGitlab : fromGitlab.getGroups()) {
				if (! user.getGroups().contains(groupFromGitlab)) {
					try {
						Group groupObj = this.findGroupByName(groupFromGitlab);
						if (groupObj == null) {
							logger.warn("Group " + groupFromGitlab + " does not exist");
						} else {
							this.groupApi.removeMember(groupObj.getId(), toSave.getId());
							this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Delete,  approvalID, workflow, "group", groupFromGitlab);
						}
					} catch (GitLabApiException e) {
						throw new ProvisioningException("Could not find group " + groupFromGitlab);
					}
				}
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
		
		org.gitlab4j.api.models.User fromGitlab = this.findUserByName(user.getUserID());
		
		if (fromGitlab == null) {
			return;
		}
		
		try {
			this.userApi.deleteUser(fromGitlab.getId(),false);
		} catch (GitLabApiException e) {
			throw new ProvisioningException("Could not delete " + user.getUserID(),e);
		}
		
		
		this.cfgMgr.getProvisioningEngine().logAction(this.name,true, ActionType.Delete,  approvalID, workflow, "id", fromGitlab.getId().toString());

	}

	@Override
	public User findUser(String userID, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		
		org.gitlab4j.api.models.User fromGitlab = findUserByName(userID);
		
		if (fromGitlab == null) {
			return null;
		}
		
		User forUnison = new User(userID);
		
		for (String attrName : attributes) {
			
			
			try {
				String val = beanUtils.getProperty(fromGitlab, attrName);
				if (val != null) {
					Attribute attr = new Attribute(attrName,val);
					forUnison.getAttribs().put(attrName, attr);
				}
			} catch (IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
				throw new ProvisioningException("Couldn't load attribute " + attrName,e);
			}
		}
		
		if (fromGitlab.getIdentities() != null) {
			ArrayList<GitlabFedIdentity> ids = new ArrayList<GitlabFedIdentity>();
			for (Identity fedid : fromGitlab.getIdentities()) {
				GitlabFedIdentity id = new GitlabFedIdentity();
				id.setExternalUid(fedid.getExternUid());
				id.setProvider(fedid.getProvider());
				ids.add(id);
			}
			
			request.put(GitlabUserProvider.GITLAB_IDENTITIES,ids);
		}
		
		
		ArrayList<Header> defheaders = new ArrayList<Header>();
		defheaders.add(new BasicHeader("Private-Token", this.token));

		BasicHttpClientConnectionManager bhcm = new BasicHttpClientConnectionManager(
				cfgMgr.getHttpClientSocketRegistry());

		RequestConfig rc = RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD).setRedirectsEnabled(false)
				.build();

		CloseableHttpClient http = HttpClients.custom()
				                  .setConnectionManager(bhcm)
				                  .setDefaultHeaders(defheaders)
				                  .setDefaultRequestConfig(rc)
				                  .build();
		
		try {
			HttpGet getmembers = new HttpGet(new StringBuilder().append(this.url).append("/api/v4/users/").append(fromGitlab.getId()).append("/memberships").toString());
			CloseableHttpResponse resp = http.execute(getmembers);
			
			if (resp.getStatusLine().getStatusCode() != 200) {
				throw new IOException("Invalid response " + resp.getStatusLine().getStatusCode());
			}
			
			String json = EntityUtils.toString(resp.getEntity());
			
			JSONArray members = (JSONArray) new JSONParser().parse(json);
			
			for (Object o : members) {
				JSONObject member = (JSONObject) o;
				String sourceType = (String) member.get("source_type");
				String sourceName = (String) member.get("source_name");
				
				if (sourceType.equalsIgnoreCase("Namespace")) {
					forUnison.getGroups().add(sourceName);
				}
			}
			
		} catch (IOException | ParseException e) {
			throw new ProvisioningException("Could not get group memebers",e);
		} finally {
			try {
				http.close();
			} catch (IOException e) {
				
			}
			
			bhcm.close();
			
		}
		
		return forUnison;
	}



	private org.gitlab4j.api.models.User findUserByName(String userID) throws ProvisioningException {
		org.gitlab4j.api.models.User fromGitlab;
		
		try {
			List<org.gitlab4j.api.models.User> users = this.userApi.findUsers(userID);
			if (users.size() == 0) {
				return null;
			} else if (users.size() > 1) {
				throw new ProvisioningException(userID + " maps to multiple users");
			} else {
				fromGitlab = users.get(0);
			}
		} catch (GitLabApiException e) {
			throw new ProvisioningException("Could not load user",e);
		}
		return fromGitlab;
	}

	@Override
	public void init(Map<String, Attribute> cfg, ConfigManager cfgMgr, String name) throws ProvisioningException {
		this.token = cfg.get("token").getValues().get(0);
        this.url = cfg.get("url").getValues().get(0);
        this.name = name;
        
        this.gitLabApi = new GitLabApi(this.url, this.token);
        this.userApi = new UserApi(this.gitLabApi);
        this.groupApi = new GroupApi(this.gitLabApi);
        
        this.cfgMgr = cfgMgr;


	}

	@Override
	public void addGroup(String name, Map<String, String> additionalAttributes, User user, Map<String, Object> request)
			throws ProvisioningException {
		if (this.isGroupExists(name, null, request)) {
			return;
		}
		
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		Group groupToCreate = new Group();
		groupToCreate.setName(name);
		groupToCreate.setPath(name);
		
		for (String prop : additionalAttributes.keySet()) {
			try {
				this.beanUtils.setProperty(groupToCreate, prop, additionalAttributes.get(prop));
			} catch (IllegalAccessException | InvocationTargetException e) {
				throw new ProvisioningException("Could not set properties",e);
			}
		}
		
		try {
			this.groupApi.addGroup(groupToCreate);
		} catch (GitLabApiException e) {
			throw new ProvisioningException("Could not create group " + name,e);
		}

		
		this.cfgMgr.getProvisioningEngine().logAction(this.name,true, ActionType.Add,  approvalID, workflow, "group-object", name);
		
	}

	@Override
	public void deleteGroup(String name, User user, Map<String, Object> request) throws ProvisioningException {
		if (! this.isGroupExists(name, null, request)) {
			return;
		}
		
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		try {
			this.groupApi.deleteGroup(name);
		} catch (GitLabApiException e) {
			throw new ProvisioningException("Could not delete group " + name,e);
		}
		
		this.cfgMgr.getProvisioningEngine().logAction(this.name,true, ActionType.Delete,  approvalID, workflow, "group-object", name);

	}

	@Override
	public boolean isGroupExists(String name, User user, Map<String, Object> request) throws ProvisioningException {
		try {
			Group group = this.findGroupByName(name);
			return group != null;
		} catch (GitLabApiException e) {
			throw new ProvisioningException("Could not search for groups",e);
		}
	}
	
	public Group findGroupByName(String name) throws GitLabApiException {
		List<Group> groups = this.groupApi.getGroups(name);
		for (Group group : groups) {
			if (group.getName().equalsIgnoreCase(name)) {
				return group;
			}
		}
		
		return null;
	
	
	}
	
	public GitLabApi getApi() {
		return this.gitLabApi;
	}
	
	public String getName() {
		return this.name;
	}



	@Override
	public void shutdown() throws ProvisioningException {
		this.gitLabApi.close();
		
	}

}
