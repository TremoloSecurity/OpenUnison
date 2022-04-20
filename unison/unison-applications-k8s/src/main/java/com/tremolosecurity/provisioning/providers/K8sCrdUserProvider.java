/*******************************************************************************
 * Copyright 2018 Tremolo Security, Inc.
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
package com.tremolosecurity.provisioning.providers;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.logging.log4j.Logger;
import org.json.simple.JSONObject;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.myvd.K8sCrdInsert;
import com.tremolosecurity.myvd.dataObj.K8sUser;
import com.tremolosecurity.myvd.dataObj.UserData;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.UserStoreProvider;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;

import net.sourceforge.myvd.types.Entry;
import net.sourceforge.myvd.util.IteratorEntrySet;

public class K8sCrdUserProvider implements UserStoreProvider {
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(K8sCrdUserProvider.class.getName());

	String k8sTarget;
	String nameSpace;
	private Gson gson;
	private Gson gsonNoUnderScore;

	private String name;
	
	@Override
	public void createUser(User user, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		
		String k8sUserId = OpenShiftTarget.sub2uid(user.getUserID());
		
		int approvalID = 0;
		
		
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		HashMap<String,Object> createObject = new HashMap<String,Object>();
		createObject.put("apiVersion", "openunison.tremolo.io/v1");
		createObject.put("kind","User");
		HashMap<String,Object> metaData = new HashMap<String,Object>();
		createObject.put("metadata", metaData);
		metaData.put("name", k8sUserId);
		metaData.put("namespace",this.nameSpace);
		
		HashMap<String,Object> spec = new HashMap<String,Object>();
		createObject.put("spec", spec);
		
		if (attributes.contains("sub")) {
			if (user.getAttribs().get("sub") == null) {
				throw new ProvisioningException("No sub attribute");
			}
			spec.put("sub", user.getAttribs().get("sub").getValues().get(0));
		}
		
		if (attributes.contains("first_name")) {
			if (user.getAttribs().get("first_name") == null) {
				throw new ProvisioningException("No first_name attribute");
			}
			spec.put("first_name", user.getAttribs().get("first_name").getValues().get(0));
		}
		
		if (attributes.contains("last_name")) {
			if (user.getAttribs().get("last_name") == null) {
				throw new ProvisioningException("No last_name attribute");
			}
			spec.put("last_name", user.getAttribs().get("last_name").getValues().get(0));
		}
		
		if (attributes.contains("email")) {
			if (user.getAttribs().get("email") == null) {
				throw new ProvisioningException("No email attribute");
			}
			spec.put("email", user.getAttribs().get("email").getValues().get(0));
		}
		
		if (attributes.contains("uid")) {
			spec.put("uid", k8sUserId);
		}
		
		
		spec.put("groups",user.getGroups());
		
		OpenShiftTarget k8s = null;
		try {
			k8s = (OpenShiftTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(this.k8sTarget).getProvider();
		} catch (ProvisioningException e1) {
			logger.error("Could not retrieve kubernetes target",e1);
			throw new ProvisioningException("Could not connect to kubernetes",e1);
		}
		
		String url = new StringBuilder().append("/apis/openunison.tremolo.io/v1/namespaces/").append(this.nameSpace).append("/users").toString();
		try {
			HttpCon con = k8s.createClient();
			
			try {
				String jsonReq = this.gsonNoUnderScore.toJson(createObject);
				String jsonResp = k8s.callWSPost(k8s.getAuthToken(), con, url,jsonReq);
				
				
				
				K8sUser k8sUser = gson.fromJson(jsonResp, UserData.class).getSpec();
				
				
				if (k8sUser == null) {
					throw new ProvisioningException("User not created - '" + jsonResp + "'");
				}
				
				
				GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().logAction(this.name,true, ActionType.Add, approvalID, workflow,"sub", user.getUserID());
				
				if (attributes.contains("sub")) {
					GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().logAction(this.name,false, ActionType.Add, approvalID, workflow,"sub", user.getAttribs().get("sub").getValues().get(0));
				}
				
				if (attributes.contains("first_name")) {
					GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().logAction(this.name,false, ActionType.Add, approvalID, workflow,"first_name", user.getAttribs().get("first_name").getValues().get(0));
				}
				
				if (attributes.contains("last_name")) {
					GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().logAction(this.name,false, ActionType.Add, approvalID, workflow,"last_name", user.getAttribs().get("last_name").getValues().get(0));
				}
				
				if (attributes.contains("email")) {
					GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().logAction(this.name,false, ActionType.Add, approvalID, workflow,"email", user.getAttribs().get("email").getValues().get(0));
					
				}
				
				if (attributes.contains("uid")) {
					GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().logAction(this.name,false, ActionType.Add, approvalID, workflow,"uid", k8sUserId);
					
				}
				
				
				for (String group : user.getGroups()) {
					GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().logAction(this.name,false, ActionType.Add, approvalID, workflow,"group", group);
				}
				
				
			} finally {
				con.getHttp().close();
				con.getBcm().close();
			}
		} catch (Exception e) {
			logger.error("Could not search k8s",e);
			throw new ProvisioningException("Error searching kubernetes",e);
			
		}
		
		


	}

	@Override
	public void setUserPassword(User user, Map<String, Object> request) throws ProvisioningException {
		

	}

	@Override
	public void syncUser(User user, boolean addOnly, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		User fromServer = this.findUser(user.getUserID(), attributes, request);
		if (fromServer == null) {
			this.createUser(user, attributes, request);
		} else {
			
			String k8sUserId = OpenShiftTarget.sub2uid(user.getUserID());
			
			int approvalID = 0;
			
			
			if (request.containsKey("APPROVAL_ID")) {
				approvalID = (Integer) request.get("APPROVAL_ID");
			}
			
			Workflow workflow = (Workflow) request.get("WORKFLOW");
			
			OpenShiftTarget k8s = null;
			try {
				k8s = (OpenShiftTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(this.k8sTarget).getProvider();
			} catch (ProvisioningException e1) {
				logger.error("Could not retrieve kubernetes target",e1);
				throw new ProvisioningException("Could not connect to kubernetes",e1);
			}
			
			String url = new StringBuilder().append("/apis/openunison.tremolo.io/v1/namespaces/").append(this.nameSpace).append("/users/").append(k8sUserId).toString();
			
			HashMap<String,Object> patch = new HashMap<String,Object>();
			if (attributes.contains("first_name")) {
				if (! fromServer.getAttribs().get("first_name").getValues().get(0).equalsIgnoreCase(user.getAttribs().get("first_name").getValues().get(0))) {
					patch.put("first_name", user.getAttribs().get("first_name").getValues().get(0));
				}
			}
			
			if (attributes.contains("last_name")) {
				if (! fromServer.getAttribs().get("last_name").getValues().get(0).equalsIgnoreCase(user.getAttribs().get("last_name").getValues().get(0))) {
					patch.put("last_name", user.getAttribs().get("last_name").getValues().get(0));
				}
			}
			
			if (attributes.contains("email")) {
				if (! fromServer.getAttribs().get("email").getValues().get(0).equalsIgnoreCase(user.getAttribs().get("email").getValues().get(0))) {
					patch.put("email", user.getAttribs().get("email").getValues().get(0));
				}
			}
			
			
			List<String> newGroups = new ArrayList<String>();
			List<String> added = new ArrayList<String>();
			newGroups.addAll(fromServer.getGroups());
			
			for (String groupFromUser : user.getGroups()) {
				if (! newGroups.contains(groupFromUser)) {
					newGroups.add(groupFromUser);
					added.add(groupFromUser);
				}
			}
			
			List<String> removed = new ArrayList<String>();
			if (! addOnly) {
				for (String newGroup : newGroups) {
					if (! user.getGroups().contains(newGroup)) {
						removed.add(newGroup);
					}
				}
				
				if (removed.size() > 0) {
					newGroups.removeAll(removed);
				}
			}
			
			if (added.size() > 0 || removed.size() > 0) {
				patch.put("groups",newGroups);
			}
			
			if (patch.size() > 0) {
				
				JSONObject root = new JSONObject();
				JSONObject spec = new JSONObject();
				root.put("spec", spec);
				spec.putAll(patch);
				
				
				String json = root.toString();
				
				try {
					HttpCon con = k8s.createClient();
					
					try {
						k8s.callWSPatchJson(k8s.getAuthToken(), con, url,json);
						for (String attrName : patch.keySet()) {
							if (attrName.equalsIgnoreCase("groups")) {
								for (String group : added ) {
									GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().logAction(this.name,false, ActionType.Add, approvalID, workflow,"group", group);
								}
								
								for (String group : removed ) {
									GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().logAction(this.name,false, ActionType.Delete, approvalID, workflow,"group", group);
								}
							} else {
								GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().logAction(this.name,false, ActionType.Replace, approvalID, workflow,attrName, patch.get(attrName).toString());
							}
						}
						//GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().logAction(this.name,true, ActionType.Delete, approvalID, workflow,"sub", user.getUserID());
					} finally {
						con.getHttp().close();
						con.getBcm().close();
					}
					
				} catch (Exception e) {
					logger.error("Could not search k8s",e);
					throw new ProvisioningException("Error searching kubernetes",e);
					
				}
				
			}
			
			
		}

	}

	@Override
	public void deleteUser(User user, Map<String, Object> request) throws ProvisioningException {
		String k8sUserId = OpenShiftTarget.sub2uid(user.getUserID());
		
		int approvalID = 0;
		
		
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		OpenShiftTarget k8s = null;
		try {
			k8s = (OpenShiftTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(this.k8sTarget).getProvider();
		} catch (ProvisioningException e1) {
			logger.error("Could not retrieve kubernetes target",e1);
			throw new ProvisioningException("Could not connect to kubernetes",e1);
		}
		
		String url = new StringBuilder().append("/apis/openunison.tremolo.io/v1/namespaces/").append(this.nameSpace).append("/users/").append(k8sUserId).toString();
		try {
			HttpCon con = k8s.createClient();
			
			try {
				k8s.callWSDelete(k8s.getAuthToken(), con, url);
				GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().logAction(this.name,true, ActionType.Delete, approvalID, workflow,"sub", user.getUserID());
			} finally {
				con.getHttp().close();
				con.getBcm().close();
			}
			
		} catch (Exception e) {
			logger.error("Could not search k8s",e);
			throw new ProvisioningException("Error searching kubernetes",e);
			
		}
		

	}

	@Override
	public User findUser(String userID, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		String k8sUserId = OpenShiftTarget.sub2uid(userID);
		OpenShiftTarget k8s = null;
		try {
			k8s = (OpenShiftTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(this.k8sTarget).getProvider();
		} catch (ProvisioningException e1) {
			logger.error("Could not retrieve kubernetes target",e1);
			throw new ProvisioningException("Could not connect to kubernetes",e1);
		}
		
		String url = new StringBuilder().append("/apis/openunison.tremolo.io/v1/namespaces/").append(this.nameSpace).append("/users/").append(k8sUserId).toString();
		ArrayList<Entry> ret = new ArrayList<Entry>();
		try {
			HttpCon con = k8s.createClient();
			
			try {
				String jsonResp = k8s.callWS(k8s.getAuthToken(), con, url);
				
				
				
				K8sUser k8sUser = gson.fromJson(jsonResp, UserData.class).getSpec();
				
				
				if (k8sUser == null) {
					return null;
				} else {
				
					
					User user = new User(userID);
					if (attributes.contains("sub")) {
						user.getAttribs().put("sub", new Attribute("sub",k8sUser.getSub()));
					}
					
					if (attributes.contains("first_name")) {
						user.getAttribs().put("first_name", new Attribute("first_name",k8sUser.getFirstName()));
					}

					if (attributes.contains("last_name")) {
						user.getAttribs().put("last_name", new Attribute("last_name",k8sUser.getLastName()));
					}
					
					if (attributes.contains("email")) {
						user.getAttribs().put("email", new Attribute("email",k8sUser.getEmail()));
					}
					
					if (attributes.contains("uid")) {
						user.getAttribs().put("uid", new Attribute("uid",k8sUser.getUid()));
					}
					
					
				
					
					
					if (k8sUser.getGroups().size() > 0) {
						for (String group : k8sUser.getGroups()) {
							user.getGroups().add(group);
						}
					}
					
					return user;
					
				}
				
				
				
				
				
				
			} finally {
				con.getHttp().close();
				con.getBcm().close();
			}
			
		} catch (Exception e) {
			logger.error("Could not search k8s",e);
			throw new ProvisioningException("Error searching kubernetes",e);
			
		}
	}

	@Override
	public void init(Map<String, Attribute> cfg, ConfigManager cfgMgr, String name) throws ProvisioningException {
		this.k8sTarget = cfg.get("k8sTarget").getValues().get(0);
		this.nameSpace = cfg.get("nameSpace").getValues().get(0);
		
		this.gson = new GsonBuilder()
        	    .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
        	    .create();
		
		this.gsonNoUnderScore = new Gson();
		this.name = name;

	}

	@Override
	public void shutdown() throws ProvisioningException {
		
		
	}

}
