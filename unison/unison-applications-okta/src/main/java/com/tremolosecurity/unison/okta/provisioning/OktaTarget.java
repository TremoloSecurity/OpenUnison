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
package com.tremolosecurity.unison.okta.provisioning;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;


import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import com.okta.sdk.resource.client.ApiClient;
import com.okta.sdk.resource.client.ApiException;

import com.okta.sdk.client.Clients;
import com.okta.sdk.client.ClientBuilder;
import com.okta.sdk.resource.group.GroupBuilder;
import com.okta.sdk.resource.user.UserBuilder;

import com.okta.sdk.resource.api.UserApi;
import com.okta.sdk.resource.api.GroupApi;
import com.okta.sdk.resource.model.*;

import com.okta.sdk.resource.model.Group;

import com.okta.sdk.authc.credentials.TokenClientCredentials;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.ProvisioningTarget;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.UserStoreProvider;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.util.ObjUtils;

public class OktaTarget implements UserStoreProvider {
	
	String token;
	String domain;
	private ConfigManager cfgMgr;
	
	ClientBuilder builder;
    ApiClient okta;
    
    UserApi userApi = null;
    GroupApi groupApi = null;
	
	
	String name;
	@Override
	public void createUser(User user, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		com.okta.sdk.resource.model.User forOkta = null;
		UserBuilder ub = UserBuilder.instance();
		HashMap<String,String> profile = new HashMap<String,String>();
		
		for (String attrName : user.getAttribs().keySet()) {
			
			if (attributes.contains(attrName)) {
				profile.put(attrName, user.getAttribs().get(attrName).getValues().get(0));
			}
		}
		
		try {
			ObjUtils.map2props(profile, ub);
		} catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
			throw new ProvisioningException("Could not set properties",e);
		}
		
		
		
		
		for (String group : user.getGroups()) {
			List<Group> gl = this.groupApi.listGroups(group, null,null, null, null, null, null, null);
			
			ub.addGroup(gl.iterator().next().getId());
		}
		
		ub.buildAndCreate(this.userApi);
		
		this.cfgMgr.getProvisioningEngine().logAction(name,true, ActionType.Add,  approvalID, workflow, "login", user.getUserID());
		for (String attrName : user.getAttribs().keySet()) {
					
			if (attributes.contains(attrName)) {
				profile.put(attrName, user.getAttribs().get(attrName).getValues().get(0));
				this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Add,  approvalID, workflow, attrName, user.getAttribs().get(attrName).getValues().get(0));
			}
		}
		
		for (String group : user.getGroups()) {
			this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Add,  approvalID, workflow, "group", group);
		}
		
		
	}
	@Override
	public void setUserPassword(User user, Map<String, Object> request) throws ProvisioningException {
		// TODO Auto-generated method stub
		
	}
	@Override
	public void syncUser(User user, boolean addOnly, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		com.okta.sdk.resource.model.User fromOkta = null;
		Map<String,String> propsFromUser = null;
		
		try {
			fromOkta = this.userApi.getUser(user.getUserID());
			propsFromUser = ObjUtils.props2map(fromOkta);
		} catch (ApiException  e) {
			if (e.getCode() != 404) {
				throw new ProvisioningException("Could not lookup user",e);
			}
		} catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
			throw new ProvisioningException("Could not lookup user",e);
		}
		
		if (fromOkta == null) {
			this.createUser(user, attributes, request);
			
		} else {
			HashMap<String,String> changed = new HashMap<String,String>();
			
			for (String attrName : user.getAttribs().keySet()) {
				if (attributes.contains(attrName)) {
					if (propsFromUser.get(attrName) == null || ! propsFromUser.get(attrName).equalsIgnoreCase(user.getAttribs().get(attrName).getValues().get(0)) ) {
						changed.put(attrName, user.getAttribs().get(attrName).getValues().get(0));
					}
				}
				
			}
			
			for (String attrName : changed.keySet()) {
				propsFromUser.put(attrName, changed.get(attrName));
			}
			
			HashSet<String> groups = new HashSet<String>();
			List<String> groupsToAdd = new ArrayList<String>();
			List<Group> groupsFromUser = this.userApi.listUserGroups(fromOkta.getId()); 
			for (Group group : groupsFromUser) {
				groups.add(group.getProfile().getName());
			}
			
			for (String group : user.getGroups()) {
				if (! groups.contains(group)) {
					groupsToAdd.add(group);
				}
			}
			
			for (String group : groupsToAdd) {
				List<Group> gl = this.groupApi.listGroups(group, null,null, null, null, null, null, null);
				
				Group groupFromOkta = gl.iterator().next();
				groupApi.assignUserToGroup(groupFromOkta.getId(), fromOkta.getId());
				
			}
			
			for (String attrName : changed.keySet()) {
				this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Replace,  approvalID, workflow, attrName, changed.get(attrName));
			}
			
			for (String group : groupsToAdd) {
				this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Add,  approvalID, workflow, "group", group);
			}
			
			
			
			try {
				ObjUtils.map2props(changed, fromOkta.getProfile());
			} catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
				throw new ProvisioningException("Could not store user changes",e);
			}
			com.okta.sdk.resource.model.UpdateUserRequest updateRequest = new com.okta.sdk.resource.model.UpdateUserRequest();
			updateRequest.setProfile(fromOkta.getProfile());
			this.userApi.updateUser(fromOkta.getId(), updateRequest, true);
			
			List<Group> groupsToRemove = new ArrayList<Group>();
			if (! addOnly) {
				for (Group group : groupsFromUser) {
					if (! user.getGroups().contains(group.getProfile().getName())) {
						groupsToRemove.add(group);
					}
				}
				
				for (Group g : groupsToRemove) {
					if (! g.getProfile().getName().equals("Everyone")) {
						
						groupApi.unassignUserFromGroup(g.getId(), fromOkta.getId());
						
						
						this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Delete,  approvalID, workflow, "group", g.getProfile().getName());
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
		
		com.okta.sdk.resource.model.User fromOkta = null;
		
		try {
			fromOkta = this.userApi.getUser(user.getUserID());
		} catch (ApiException e) {
			throw new ProvisioningException("Could not lookup user",e);
		}
		
		this.userApi.deactivateUser(user.getUserID(), false);
		this.userApi.deleteUser(user.getUserID(), false);
		this.cfgMgr.getProvisioningEngine().logAction(name,true, ActionType.Delete,  approvalID, workflow, "login", user.getUserID());
	}
	@Override
	public User findUser(String userID, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		
		
		try {
			com.okta.sdk.resource.model.User fromOkta = null;
			
			try {
				fromOkta = userApi.getUser(userID);
			} catch (ApiException e) {
				if (e.getCode() == 404) {
					return null;
				} else {
					throw new ProvisioningException("Could not lookup user",e);
				}
			}
			
			User user = new User(userID);
			UserProfile profile = fromOkta.getProfile();
			
			Map<String,String> profileMap = ObjUtils.props2map(profile);
			
			for (Object attrKey : profileMap.keySet()) {
				String attrName = (String) attrKey;
				String value = (String) profileMap.get(attrKey);
				
				if (attributes.contains(attrName)) {
					user.getAttribs().put(attrName, new Attribute(attrName,value));
				}
				
			}
			
			
			List<Group> groups = this.userApi.listUserGroups(userID);
			for (Group group : groups) {
				user.getGroups().add(group.getProfile().getName());
			}

			
			return user;
			
				
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not retrieve user",e);
		} 
		
	}
	@Override
	public void init(Map<String, Attribute> cfg, ConfigManager cfgMgr, String name) throws ProvisioningException {
		this.cfgMgr = cfgMgr;
		
		String domainFromConfig = cfg.get("domain").getValues().get(0);
		
		if (domainFromConfig.startsWith("http")) {
			this.domain = domainFromConfig;
		} else {
			this.domain = "https://" + domainFromConfig;
		}
		
		
		
		this.token = cfg.get("token").getValues().get(0);
		
		this.builder = Clients.builder();
		this.okta = Clients.builder()
						.setOrgUrl(this.domain)
						.setClientCredentials(new TokenClientCredentials(this.token))
						.build();
		
		
		this.userApi = new UserApi(okta);
		this.groupApi = new GroupApi(okta);
		
		this.name = name;
	}

	public ApiClient getOkta() {
		return this.okta;
	}
	@Override
	public void shutdown() throws ProvisioningException {
		
		
	}
	public String getDomain() {
		return domain;
	}
	
	public UserApi getUserApi() {
		return this.userApi;
	}
	
	public GroupApi getGroupApi() {
		return this.groupApi;
	}
	
	

}
