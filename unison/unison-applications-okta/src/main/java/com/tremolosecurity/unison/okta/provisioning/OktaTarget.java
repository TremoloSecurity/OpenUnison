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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;


import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import com.okta.sdk.authc.credentials.TokenClientCredentials;
import com.okta.sdk.client.Client;
import com.okta.sdk.client.Clients;
import com.okta.sdk.resource.ResourceException;
import com.okta.sdk.resource.group.Group;
import com.okta.sdk.resource.group.GroupList;
import com.okta.sdk.resource.user.UserBuilder;
import com.okta.sdk.resource.user.UserProfile;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.ProvisioningTarget;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.UserStoreProvider;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;

public class OktaTarget implements UserStoreProvider {
	
	String token;
	String domain;
	private ConfigManager cfgMgr;
	private Client okta;
	String name;
	@Override
	public void createUser(User user, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		com.okta.sdk.resource.user.User forOkta = null;
		UserBuilder ub = UserBuilder.instance();
		HashMap<String,Object> profile = new HashMap<String,Object>();
		
		for (String attrName : user.getAttribs().keySet()) {
			
			if (attributes.contains(attrName)) {
				profile.put(attrName, user.getAttribs().get(attrName).getValues().get(0));
			}
		}
		
		ub.setProfileProperties(profile);
		
		for (String group : user.getGroups()) {
			GroupList gl = okta.listGroups(group, null,null);
			
			ub.addGroup(gl.iterator().next().getId());
		}
		
		ub.buildAndCreate(this.okta);
		
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
		
		com.okta.sdk.resource.user.User fromOkta = null;
		
		try {
			fromOkta = okta.getUser(user.getUserID());
		} catch (ResourceException e) {
			if (e.getStatus() != 404) {
				throw new ProvisioningException("Could not lookup user",e);
			}
		}
		
		if (fromOkta == null) {
			this.createUser(user, attributes, request);
			
		} else {
			HashMap<String,String> changed = new HashMap<String,String>();
			
			for (String attrName : user.getAttribs().keySet()) {
				if (attributes.contains(attrName)) {
					if (fromOkta.getProfile().get(attrName) == null || ! ((String) fromOkta.getProfile().get(attrName)).equalsIgnoreCase(user.getAttribs().get(attrName).getValues().get(0)) ) {
						changed.put(attrName, user.getAttribs().get(attrName).getValues().get(0));
					}
				}
				
			}
			
			for (String attrName : changed.keySet()) {
				fromOkta.getProfile().put(attrName, changed.get(attrName));
			}
			
			HashSet<String> groups = new HashSet<String>();
			List<String> groupsToAdd = new ArrayList<String>();
			for (Group group : fromOkta.listGroups()) {
				groups.add(group.getProfile().getName());
			}
			
			for (String group : user.getGroups()) {
				if (! groups.contains(group)) {
					groupsToAdd.add(group);
				}
			}
			
			for (String group : groupsToAdd) {
				GroupList gl = okta.listGroups(group, null,null);
				fromOkta.addToGroup(gl.iterator().next().getId());
			}
			
			for (String attrName : changed.keySet()) {
				this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Replace,  approvalID, workflow, attrName, changed.get(attrName));
			}
			
			for (String group : groupsToAdd) {
				this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Add,  approvalID, workflow, "group", group);
			}
			
			
			
			fromOkta.update();
			
			List<Group> groupsToRemove = new ArrayList<Group>();
			if (! addOnly) {
				for (Group group : fromOkta.listGroups()) {
					if (! user.getGroups().contains(group.getProfile().getName())) {
						groupsToRemove.add(group);
					}
				}
				
				for (Group g : groupsToRemove) {
					if (! g.getProfile().getName().equals("Everyone")) {
						g.removeUser(fromOkta.getId());
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
		
		com.okta.sdk.resource.user.User fromOkta = null;
		
		try {
			fromOkta = okta.getUser(user.getUserID());
		} catch (ResourceException e) {
			throw new ProvisioningException("Could not lookup user",e);
		}
		
		fromOkta.deactivate();
		fromOkta.delete();
		this.cfgMgr.getProvisioningEngine().logAction(name,true, ActionType.Delete,  approvalID, workflow, "login", user.getUserID());
	}
	@Override
	public User findUser(String userID, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		
		
		try {
			com.okta.sdk.resource.user.User fromOkta = null;
			
			try {
				fromOkta = okta.getUser(userID);
			} catch (ResourceException e) {
				if (e.getStatus() == 404) {
					return null;
				} else {
					throw new ProvisioningException("Could not lookup user",e);
				}
			}
			
			User user = new User(userID);
			UserProfile profile = fromOkta.getProfile();
			
			
			for (Object attrKey : profile.keySet()) {
				String attrName = (String) attrKey;
				String value = (String) profile.get(attrKey);
				
				if (attributes.contains(attrName)) {
					user.getAttribs().put(attrName, new Attribute(attrName,value));
				}
				
			}
			
			
			GroupList groups = fromOkta.listGroups();
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
		this.domain = "https://" + cfg.get("domain").getValues().get(0);
		
		this.token = cfg.get("token").getValues().get(0);
		
		this.okta = Clients.builder()
			    .setOrgUrl(this.domain)
			    .setClientCredentials(new TokenClientCredentials(this.token))
			    .build();
		this.name = name;
	}

	public Client getOkta() {
		return this.okta;
	}
	@Override
	public void shutdown() throws ProvisioningException {
		
		
	}
	
	

}
