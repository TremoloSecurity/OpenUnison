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
package com.tremolosecurity.unison.openstack;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.utils.URLEncodedUtils;
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
import com.google.gson.GsonBuilder;
import com.google.gson.internal.LinkedTreeMap;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.UserStoreProvider;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.unison.openstack.model.DomainsResponse;
import com.tremolosecurity.unison.openstack.model.GroupLookupResponse;
import com.tremolosecurity.unison.openstack.model.GroupResponse;
import com.tremolosecurity.unison.openstack.model.KSDomain;
import com.tremolosecurity.unison.openstack.model.KSGroup;
import com.tremolosecurity.unison.openstack.model.KSRole;
import com.tremolosecurity.unison.openstack.model.KSRoleAssignment;
import com.tremolosecurity.unison.openstack.model.KSUser;
import com.tremolosecurity.unison.openstack.model.LoadRoleResponse;
import com.tremolosecurity.unison.openstack.model.ProjectsResponse;
import com.tremolosecurity.unison.openstack.model.Role;
import com.tremolosecurity.unison.openstack.model.RoleAssignmentResponse;
import com.tremolosecurity.unison.openstack.model.RoleResponse;
import com.tremolosecurity.unison.openstack.model.TokenRequest;
import com.tremolosecurity.unison.openstack.model.TokenResponse;
import com.tremolosecurity.unison.openstack.model.UserAndID;
import com.tremolosecurity.unison.openstack.model.UserHolder;
import com.tremolosecurity.unison.openstack.model.UserLookupResponse;
import com.tremolosecurity.unison.openstack.model.token.Identity;
import com.tremolosecurity.unison.openstack.model.token.Project;
import com.tremolosecurity.unison.openstack.model.token.Scope;
import com.tremolosecurity.unison.openstack.model.token.Token;
import com.tremolosecurity.unison.openstack.util.KSToken;

public class KeystoneProvisioningTarget implements UserStoreProvider {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(KeystoneProvisioningTarget.class.getName());
	
	String userName;
	String password;
	String domain;
	String url;
	String projectName;
	String projectDomainName;
	String usersDomain;
	boolean rolesOnly;

	private ConfigManager cfgMgr;
	
	
	@Override
	public void createUser(User user, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		
		if (rolesOnly) {
			throw new ProvisioningException("Unsupported");
		}
		
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		KSUser newUser = new KSUser();
		newUser.setDomain_id(this.usersDomain);
		newUser.setName(user.getUserID());
		newUser.setEnabled(true);
		
		if (attributes.contains("email") && user.getAttribs().containsKey("email")) {
			newUser.setEmail(user.getAttribs().get("email").getValues().get(0));
		}
		
		if (attributes.contains("description") && user.getAttribs().containsKey("description")) {
			newUser.setEmail(user.getAttribs().get("description").getValues().get(0));
		}
		
		HttpCon con = null;
		KSUser fromKS = null;
		try {
			con = this.createClient();
			KSToken token = this.getToken(con);
			Gson gson = new Gson();
			UserHolder userHolder = new UserHolder();
			userHolder.setUser(newUser);
			String json = gson.toJson(userHolder);
			
			StringBuffer b = new StringBuffer();
			b.append(this.url).append("/users");
			json = this.callWSPost(token.getAuthToken(), con,b.toString() , json);
			if (json == null) {
				throw new Exception("Could not create user");
			}
			
			
			
			UserHolder createdUser = gson.fromJson(json, UserHolder.class);
			
			if (createdUser.getUser() == null) {
				throw new ProvisioningException("Could not create user :" + json);
			}
			
			
			this.cfgMgr.getProvisioningEngine().logAction(user.getUserID(),true, ActionType.Add,  approvalID, workflow, "name", user.getUserID());
			this.cfgMgr.getProvisioningEngine().logAction(user.getUserID(),false, ActionType.Add,  approvalID, workflow, "name", user.getUserID());
			this.cfgMgr.getProvisioningEngine().logAction(user.getUserID(),false, ActionType.Add,  approvalID, workflow, "domain_id", this.usersDomain);
			this.cfgMgr.getProvisioningEngine().logAction(user.getUserID(),false, ActionType.Add,  approvalID, workflow, "enabled", "true");
			if (attributes.contains("email")) {
				this.cfgMgr.getProvisioningEngine().logAction(user.getUserID(),false, ActionType.Add,  approvalID, workflow, "email", user.getAttribs().get("email").getValues().get(0));
			}
			if (attributes.contains("description")) {
				this.cfgMgr.getProvisioningEngine().logAction(user.getUserID(),false, ActionType.Add,  approvalID, workflow, "description", user.getAttribs().get("description").getValues().get(0));
			}
			
			
			
			
			
			for (String group : user.getGroups()) {
				String groupID = this.getGroupID(token.getAuthToken(), con, group);
				b.setLength(0);
				b.append(this.url).append("/groups/").append(groupID).append("/users/").append(createdUser.getUser().getId());
				if (this.callWSPutNoData(token.getAuthToken(), con, b.toString())) {
					this.cfgMgr.getProvisioningEngine().logAction(user.getUserID(),false, ActionType.Add,  approvalID, workflow, "group", group);
					
				} else {
					throw new ProvisioningException("Could not add group " + group);
				}
				
			}
			
			if (attributes.contains("roles")) {
				Attribute roles = user.getAttribs().get("roles");
				for (String roleJSON : roles.getValues()) {
					Role role = gson.fromJson(roleJSON, Role.class);
					if (role.getScope().equalsIgnoreCase("project")) {
						String projectid = this.getProjectID(token.getAuthToken(), con, role.getProject());
						if (projectid == null) {
							throw new ProvisioningException("Project " + role.getDomain() + " does not exist");
						}
						
						String roleid = this.getRoleID(token.getAuthToken(), con, role.getName());
						if (roleid == null) {
							throw new ProvisioningException("Role " + role.getName() + " does not exist");
						}
						
						b.setLength(0);
						b.append(this.url).append("/projects/").append(projectid).append("/users/").append(createdUser.getUser().getId()).append("/roles/").append(roleid);
						
						if (this.callWSPutNoData(token.getAuthToken(), con, b.toString())) {
							this.cfgMgr.getProvisioningEngine().logAction(user.getUserID(),false, ActionType.Add,  approvalID, workflow, "role", roleJSON);
						} else {
							throw new ProvisioningException("Could not add role " + roleJSON);
						} 
					} else {
						String domainid = this.getDomainID(token.getAuthToken(), con, role.getDomain());
						if (domainid == null) {
							throw new ProvisioningException("Domain " + role.getDomain() + " does not exist");
						}
						
						String roleid = this.getRoleID(token.getAuthToken(), con, role.getName());
						if (roleid == null) {
							throw new ProvisioningException("Role " + role.getName() + " does not exist");
						}
						
						b.setLength(0);
						b.append(this.url).append("/domains/").append(domainid).append("/users/").append(createdUser.getUser().getId()).append("/roles/").append(roleid);
						
						if (this.callWSPutNoData(token.getAuthToken(), con, b.toString())) {
							this.cfgMgr.getProvisioningEngine().logAction(user.getUserID(),false, ActionType.Add,  approvalID, workflow, "role", roleJSON);
						} else {
							throw new ProvisioningException("Could not add role " + roleJSON);
						}
					}
				}
			}
				
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not work with keystone",e);
		} finally {
			if (con != null) {
				con.getBcm().shutdown();
			}
		}
	}

	@Override
	public void setUserPassword(User user, Map<String, Object> request) throws ProvisioningException {
		if (rolesOnly) {
			throw new ProvisioningException("Unsupported");
		}
		
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		HttpCon con = null;
		
		String id;
		if (user.getAttribs().get("id") != null) {
			id = user.getAttribs().get("id").getValues().get(0);
		} else {
			HashSet<String> attrs = new HashSet<String>();
			attrs.add("id");
			User userFromKS = this.findUser(user.getUserID(), attrs, request);
			id = userFromKS.getAttribs().get("id").getValues().get(0);
		}
		
		UserHolder holder = new UserHolder();
		holder.setUser(new KSUser());
		
		holder.getUser().setPassword(user.getPassword());
		
		Gson gson = new Gson();
		
		
		KSUser fromKS = null;
		try {
			con = this.createClient();
			KSToken token = this.getToken(con);
			String json = gson.toJson(holder);
			StringBuffer b = new StringBuffer();
			b.append(this.url).append("/users/").append(id);
			json = this.callWSPotch(token.getAuthToken(), con, b.toString(), json);
			this.cfgMgr.getProvisioningEngine().logAction(user.getUserID(),false, ActionType.Replace,  approvalID, workflow, "password", "***********");
		} catch (Exception e) {
			throw new ProvisioningException("Could not work with keystone",e);
		} finally {
			if (con != null) {
				con.getBcm().shutdown();
			}
		}	

	}

	@Override
	public void syncUser(User user, boolean addOnly, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		HttpCon con = null;
		Gson gson = new Gson();
		
		
		
		try {
			con = this.createClient();
			KSToken token = this.getToken(con);
			
			UserAndID fromKS = this.lookupUser(user.getUserID(), attributes, request, token, con);
			
			if (fromKS == null) {
				this.createUser(user, attributes, request);
			} else {
				//check attributes
				HashMap<String,String> attrsUpdate = new HashMap<String,String>();
				KSUser toPatch = new KSUser();
				
				if (! rolesOnly) {
					if (attributes.contains("email")) {
						String fromKSVal = null;
						String newVal = null;
						
						if (fromKS.getUser().getAttribs().get("email") != null) {
							fromKSVal = fromKS.getUser().getAttribs().get("email").getValues().get(0);
						}
						
						if (user.getAttribs().get("email") != null) {
							newVal = user.getAttribs().get("email").getValues().get(0);
						}
						
						if (newVal != null && (fromKSVal == null || ! fromKSVal.equalsIgnoreCase(newVal))) {
							toPatch.setEmail(newVal);
							attrsUpdate.put("email", newVal);
						} else if (! addOnly && newVal == null && fromKSVal != null) {
							toPatch.setEmail("");
							attrsUpdate.put("email", "");
						}
					}
					
					if (attributes.contains("enabled")) {
						String fromKSVal = null;
						String newVal = null;
						
						if (fromKS.getUser().getAttribs().get("enabled") != null) {
							fromKSVal = fromKS.getUser().getAttribs().get("enabled").getValues().get(0);
						}
						
						if (user.getAttribs().get("enabled") != null) {
							newVal = user.getAttribs().get("enabled").getValues().get(0);
						}
						
						if (newVal != null && (fromKSVal == null || ! fromKSVal.equalsIgnoreCase(newVal))) {
							toPatch.setName(newVal);
							attrsUpdate.put("enabled", newVal);
						} else if (! addOnly && newVal == null && fromKSVal != null) {
							toPatch.setEnabled(false);
							attrsUpdate.put("enabled", "");
						}
						
						
					}
					
					if (attributes.contains("description")) {
						String fromKSVal = null;
						String newVal = null;
						
						if (fromKS.getUser().getAttribs().get("description") != null) {
							fromKSVal = fromKS.getUser().getAttribs().get("description").getValues().get(0);
						}
						
						if (user.getAttribs().get("description") != null) {
							newVal = user.getAttribs().get("description").getValues().get(0);
						}
						
						if (newVal != null && (fromKSVal == null || ! fromKSVal.equalsIgnoreCase(newVal))) {
							toPatch.setDescription(newVal);
							attrsUpdate.put("description", newVal);
						} else if (! addOnly && newVal == null && fromKSVal != null) {
							toPatch.setDescription("");
							attrsUpdate.put("description", "");
						}
						
						
					}
					
					if (! attrsUpdate.isEmpty()) {
						UserHolder holder = new UserHolder();
						holder.setUser(toPatch);
						String json = gson.toJson(holder);
						StringBuffer b = new StringBuffer();
						b.append(this.url).append("/users/").append(fromKS.getId());
						json = this.callWSPotch(token.getAuthToken(), con, b.toString(), json);
						
						for (String attr : attrsUpdate.keySet()) {
							String val = attrsUpdate.get(attr);
							this.cfgMgr.getProvisioningEngine().logAction(user.getUserID(),false, ActionType.Replace,  approvalID, workflow, attr,val);
						}
						
						
					}
					
					for (String group : user.getGroups()) {
						if (! fromKS.getUser().getGroups().contains(group)) {
							String groupID = this.getGroupID(token.getAuthToken(), con, group);
							StringBuffer b = new StringBuffer();
							b.append(this.url).append("/groups/").append(groupID).append("/users/").append(fromKS.getId());
							if (this.callWSPutNoData(token.getAuthToken(), con, b.toString())) {
								this.cfgMgr.getProvisioningEngine().logAction(user.getUserID(),false, ActionType.Add,  approvalID, workflow, "group", group);
								
							} else {
								throw new ProvisioningException("Could not add group " + group);
							}
						}
					}
					
					if (! addOnly) {
						for (String group : fromKS.getUser().getGroups()) {
							if (! user.getGroups().contains(group)) {
								String groupID = this.getGroupID(token.getAuthToken(), con, group);
								StringBuffer b = new StringBuffer();
								b.append(this.url).append("/groups/").append(groupID).append("/users/").append(fromKS.getId());
								this.callWSDelete(token.getAuthToken(), con, b.toString());
								this.cfgMgr.getProvisioningEngine().logAction(user.getUserID(),false, ActionType.Delete,  approvalID, workflow, "group", group);
							}
						}
					}
				}
				
				if (attributes.contains("roles")) {
					HashSet<Role> currentRoles = new HashSet<Role>();
					if (fromKS.getUser().getAttribs().get("roles") != null) {
						Attribute attr = fromKS.getUser().getAttribs().get("roles");
						for (String jsonRole : attr.getValues()) {
							currentRoles.add(gson.fromJson(jsonRole, Role.class));
						}
					}
					
					if (user.getAttribs().containsKey("roles")) {
						StringBuffer b = new StringBuffer();
						Attribute attr = user.getAttribs().get("roles");
						for (String jsonRole : attr.getValues()) {
							Role role = gson.fromJson(jsonRole, Role.class);
							if (! currentRoles.contains(role)) {
								
								if (role.getScope().equalsIgnoreCase("project")) {
									String projectid = this.getProjectID(token.getAuthToken(), con, role.getProject());
									if (projectid == null) {
										throw new ProvisioningException("Project " + role.getDomain() + " does not exist");
									}
									
									String roleid = this.getRoleID(token.getAuthToken(), con, role.getName());
									if (roleid == null) {
										throw new ProvisioningException("Role " + role.getName() + " does not exist");
									}
									
									b.setLength(0);
									b.append(this.url).append("/projects/").append(projectid).append("/users/").append(fromKS.getId()).append("/roles/").append(roleid);
									
									if (this.callWSPutNoData(token.getAuthToken(), con, b.toString())) {
										this.cfgMgr.getProvisioningEngine().logAction(user.getUserID(),false, ActionType.Add,  approvalID, workflow, "role", jsonRole);
									} else {
										throw new ProvisioningException("Could not add role " + jsonRole);
									} 
								} else {
									String domainid = this.getDomainID(token.getAuthToken(), con, role.getDomain());
									if (domainid == null) {
										throw new ProvisioningException("Domain " + role.getDomain() + " does not exist");
									}
									
									String roleid = this.getRoleID(token.getAuthToken(), con, role.getName());
									if (roleid == null) {
										throw new ProvisioningException("Role " + role.getName() + " does not exist");
									}
									
									b.setLength(0);
									b.append(this.url).append("/domains/").append(domainid).append("/users/").append(fromKS.getId()).append("/roles/").append(roleid);
									
									if (this.callWSPutNoData(token.getAuthToken(), con, b.toString())) {
										this.cfgMgr.getProvisioningEngine().logAction(user.getUserID(),false, ActionType.Add,  approvalID, workflow, "role", jsonRole);
									} else {
										throw new ProvisioningException("Could not add role " + jsonRole);
									}
								}
							}
						}
					}
				}
				
				
				
				if (! addOnly) {
					if (attributes.contains("roles")) {
						HashSet<Role> currentRoles = new HashSet<Role>();
						if (user.getAttribs().get("roles") != null) {
							Attribute attr = user.getAttribs().get("roles");
							for (String jsonRole : attr.getValues()) {
								currentRoles.add(gson.fromJson(jsonRole, Role.class));
							}
						}
						
						if (fromKS.getUser().getAttribs().containsKey("roles")) {
							StringBuffer b = new StringBuffer();
							Attribute attr = fromKS.getUser().getAttribs().get("roles");
							for (String jsonRole : attr.getValues()) {
								Role role = gson.fromJson(jsonRole, Role.class);
								if (! currentRoles.contains(role)) {
									
									if (role.getScope().equalsIgnoreCase("project")) {
										String projectid = this.getProjectID(token.getAuthToken(), con, role.getProject());
										if (projectid == null) {
											throw new ProvisioningException("Project " + role.getDomain() + " does not exist");
										}
										
										String roleid = this.getRoleID(token.getAuthToken(), con, role.getName());
										if (roleid == null) {
											throw new ProvisioningException("Role " + role.getName() + " does not exist");
										}
										
										b.setLength(0);
										b.append(this.url).append("/projects/").append(projectid).append("/users/").append(fromKS.getId()).append("/roles/").append(roleid);
										
										this.callWSDelete(token.getAuthToken(), con, b.toString());
										this.cfgMgr.getProvisioningEngine().logAction(user.getUserID(),false, ActionType.Delete,  approvalID, workflow, "role", jsonRole);
										 
									} else {
										String domainid = this.getDomainID(token.getAuthToken(), con, role.getDomain());
										if (domainid == null) {
											throw new ProvisioningException("Domain " + role.getDomain() + " does not exist");
										}
										
										String roleid = this.getRoleID(token.getAuthToken(), con, role.getName());
										if (roleid == null) {
											throw new ProvisioningException("Role " + role.getName() + " does not exist");
										}
										
										b.setLength(0);
										b.append(this.url).append("/domains/").append(domainid).append("/users/").append(fromKS.getId()).append("/roles/").append(roleid);
										
										this.callWSDelete(token.getAuthToken(), con, b.toString());
										this.cfgMgr.getProvisioningEngine().logAction(user.getUserID(),false, ActionType.Delete,  approvalID, workflow, "role", jsonRole);
										
									}
								}
							}
						} 
					}
				}
				
			}
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not work with keystone",e);
		} finally {
			if (con != null) {
				con.getBcm().shutdown();
			}
		}	

	}

	@Override
	public void deleteUser(User user, Map<String, Object> request) throws ProvisioningException {
		
		if (rolesOnly) {
			throw new ProvisioningException("Unsupported");
		}
		
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		HttpCon con = null;
		KSUser fromKS = null;
		try {
			con = this.createClient();
			KSToken token = this.getToken(con);
			
			String id;
			if (user.getAttribs().get("id") != null) {
				id = user.getAttribs().get("id").getValues().get(0);
			} else {
				HashSet<String> attrs = new HashSet<String>();
				attrs.add("id");
				User userFromKS = this.findUser(user.getUserID(), attrs, request);
				id = userFromKS.getAttribs().get("id").getValues().get(0);
			}
			
			StringBuffer b = new StringBuffer(this.url).append("/users/").append(id);
			this.callWSDelete(token.getAuthToken(), con, b.toString());
			
			this.cfgMgr.getProvisioningEngine().logAction(user.getUserID(),true, ActionType.Delete,  approvalID, workflow, "name", user.getUserID());
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not work with keystone",e);
		} finally {
			if (con != null) {
				con.getBcm().shutdown();
			}
		}
	}

	
	public UserAndID lookupUser(String userID, Set<String> attributes, Map<String, Object> request,KSToken token,HttpCon con)
			throws Exception {
		
		KSUser fromKS = null;
		
			
			List<NameValuePair> qparams = new ArrayList<NameValuePair>();
			qparams.add(new BasicNameValuePair("domain_id",this.usersDomain));
			qparams.add(new BasicNameValuePair("name",userID));
			
			StringBuffer b = new StringBuffer();
			b.append(this.url).append("/users?").append(URLEncodedUtils.format(qparams, "UTF-8"));
			String fullURL = b.toString();
			String json = this.callWS(token.getAuthToken(), con, fullURL);
			
			
			
			Gson gson = new Gson();
			UserLookupResponse resp = gson.fromJson(json, UserLookupResponse.class);
			
			if (resp.getUsers().isEmpty()) {
				return null;
			} else {
				fromKS = resp.getUsers().get(0);
				
				User user = new User(fromKS.getName());
				
				if (attributes.contains("name")) {
					user.getAttribs().put("name", new Attribute("name",fromKS.getName()));
				}
				
				if (attributes.contains("id")) {
					user.getAttribs().put("id", new Attribute("id",fromKS.getId()));
				}
				
				if (attributes.contains("email") && fromKS.getEmail() != null) {
					user.getAttribs().put("email", new Attribute("email",fromKS.getEmail()));
				}
				
				if (attributes.contains("description") && fromKS.getDescription() != null) {
					user.getAttribs().put("description", new Attribute("description",fromKS.getEmail()));
				}
				
				
				
				if (attributes.contains("enabled")) {
					user.getAttribs().put("enabled", new Attribute("enabled",Boolean.toString(fromKS.getEnabled())));
				}
				
				
				if (! rolesOnly) { 
					b.setLength(0);
					b.append(this.url).append("/users/").append(fromKS.getId()).append("/groups");
					json = this.callWS(token.getAuthToken(), con, b.toString());
					
					GroupLookupResponse gresp = gson.fromJson(json, GroupLookupResponse.class);
					
					for (KSGroup group : gresp.getGroups()) {
						user.getGroups().add(group.getName());
					}
				}
				
				
				if (attributes.contains("roles")) {
					b.setLength(0);
					b.append(this.url).append("/role_assignments?user.id=").append(fromKS.getId()).append("&include_names=true");
					json = this.callWS(token.getAuthToken(), con, b.toString());
					
					RoleAssignmentResponse rar = gson.fromJson(json, RoleAssignmentResponse.class);
					Attribute attr = new Attribute("roles");
					for (KSRoleAssignment role : rar.getRole_assignments()) {
						if (role.getScope().getProject() != null) {
							attr.getValues().add(gson.toJson(new Role(role.getRole().getName(),"project",role.getScope().getProject().getDomain().getName(),role.getScope().getProject().getName())));
						} else {
							attr.getValues().add(gson.toJson(new Role(role.getRole().getName(),"domain",role.getScope().getDomain().getName())));
						}
					}
					
					if (! attr.getValues().isEmpty()) {
						user.getAttribs().put("roles", attr);
					}
				
				}
				
				UserAndID userAndId = new UserAndID();
				userAndId.setUser(user);
				userAndId.setId(fromKS.getId());
				
				return userAndId;
			}
			
			
			
			
		
	}
	
	@Override
	public User findUser(String userID, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		HttpCon con = null;
		try {
			con = this.createClient();
			KSToken token = this.getToken(con);
			
			UserAndID found = this.lookupUser(userID, attributes, request, token, con);
			if (found != null) {
				return found.getUser();
			} else {
				return null;
			}
		
		} catch (Exception e) {
			throw new ProvisioningException("Could not work with keystone",e);
		} finally {
			if (con != null) {
				con.getBcm().shutdown();
			}
		}
		
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
	

	
	@Override
	public void init(Map<String, Attribute> cfg, ConfigManager cfgMgr, String name) throws ProvisioningException {
		this.url = this.loadOption("url", cfg, false);
		this.userName = this.loadOption("userName", cfg, false);
		this.password = this.loadOption("password", cfg, true);
		this.domain = this.loadOption("domain", cfg, false);
		this.projectDomainName = this.loadOption("projectDomainName", cfg, false);
		this.projectName = this.loadOption("projectName", cfg, false);
		this.usersDomain = this.loadOption("usersDomain", cfg, false);
		this.rolesOnly = this.loadOption("rolesOnly", cfg, false).equalsIgnoreCase("true");
		this.cfgMgr = cfgMgr;
	}
	
	public KSToken getToken(HttpCon con) throws Exception {
		Gson gson = new Gson();
		StringBuffer b = new StringBuffer();
		b.append(this.url).append("/auth/tokens");
		
		HttpPost put = new HttpPost(b.toString());
		
		TokenRequest req = new TokenRequest();
		req.getAuth().setIdentity(new Identity());
		req.getAuth().setScope(new Scope());
		req.getAuth().getIdentity().getMethods().add("password");
		req.getAuth().getIdentity().getPassword().getUser().setDomain(new KSDomain());
		req.getAuth().getIdentity().getPassword().getUser().getDomain().setName(this.domain);
		req.getAuth().getIdentity().getPassword().getUser().setName(this.userName);
		req.getAuth().getIdentity().getPassword().getUser().setPassword(this.password);
		req.getAuth().getScope().setProject(new Project());
		req.getAuth().getScope().getProject().setName(this.projectName);
		req.getAuth().getScope().getProject().setDomain(new KSDomain());
		req.getAuth().getScope().getProject().getDomain().setName(this.projectDomainName);
		
		String json = gson.toJson(req);
		
		StringEntity str = new StringEntity(json,ContentType.APPLICATION_JSON);
		put.setEntity(str);
		
		HttpResponse resp = con.getHttp().execute(put);
		
		if (resp.getStatusLine().getStatusCode() == 201) {
			json = EntityUtils.toString(resp.getEntity());
			TokenResponse token = gson.fromJson(json, TokenResponse.class);
			String authToken = resp.getHeaders("X-Subject-Token")[0].getValue();
			
			return new KSToken(authToken,token.getToken());
		} else {
			throw new Exception("Could not authenticate to keystone");
		}
			
	}
	
	public HttpCon createClient() throws Exception {
		ArrayList<Header> defheaders = new ArrayList<Header>();
		

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
	
	public String callWS(String token, HttpCon con,String uri) throws IOException, ClientProtocolException {
		
		
		
		HttpGet get = new HttpGet(uri);
		get.addHeader(new BasicHeader("X-Auth-Token",token));
		HttpResponse resp = con.getHttp().execute(get);
		String json = EntityUtils.toString(resp.getEntity());
		return json;
	}
	
	public boolean callWSPutNoData(String token, HttpCon con,String uri) throws IOException, ClientProtocolException {
		
		
		
		HttpPut get = new HttpPut(uri);
		get.addHeader(new BasicHeader("X-Auth-Token",token));
		HttpResponse resp = con.getHttp().execute(get);
		return resp.getStatusLine().getStatusCode() == 204;
	}
	
	public String callWSDelete(String token, HttpCon con,String uri) throws IOException, ClientProtocolException {
		
		
		
		HttpDelete del = new HttpDelete(uri);
		del.addHeader(new BasicHeader("X-Auth-Token",token));
		HttpResponse resp = con.getHttp().execute(del);
		if (resp.getEntity() != null) {
			String json = EntityUtils.toString(resp.getEntity());
			return json;
		} else {
			return null;
		}
	}
	
	private String callWSPost(String token, HttpCon con,String uri,String json) throws IOException, ClientProtocolException {
		
		HttpPost put = new HttpPost(uri);
		
		put.addHeader(new BasicHeader("X-Auth-Token",token));
		
		StringEntity str = new StringEntity(json,ContentType.APPLICATION_JSON);
		put.setEntity(str);
		
		HttpResponse resp = con.getHttp().execute(put);
		
		json = EntityUtils.toString(resp.getEntity());
		return json;
	}
	
	private String callWSPotch(String token, HttpCon con,String uri,String json) throws IOException, ClientProtocolException {
		
		HttpPatch put = new HttpPatch(uri);
		
		put.addHeader(new BasicHeader("X-Auth-Token",token));
		
		StringEntity str = new StringEntity(json,ContentType.APPLICATION_JSON);
		put.setEntity(str);
		
		HttpResponse resp = con.getHttp().execute(put);
		
		json = EntityUtils.toString(resp.getEntity());
		return json;
	}
	
	private String getGroupID(String token,HttpCon con,String name) throws Exception {
		StringBuffer b = new StringBuffer();
		b.append(this.url).append("/groups?name=").append(URLEncoder.encode(name, "UTF-8"));
		String json = this.callWS(token, con, b.toString());
		Gson gson = new Gson();
		GroupResponse resp = gson.fromJson(json, GroupResponse.class);
		if (resp.getGroups().isEmpty()) {
			return null;
		} else {
			return resp.getGroups().get(0).getId();
		}
	}

	private String getRoleID(String token,HttpCon con,String name) throws Exception {
		StringBuffer b = new StringBuffer();
		b.append(this.url).append("/roles?name=").append(URLEncoder.encode(name, "UTF-8"));
		String json = this.callWS(token, con, b.toString());
		Gson gson = new Gson();
		LoadRoleResponse resp = gson.fromJson(json, LoadRoleResponse.class);
		if (resp.getRoles().isEmpty()) {
			return null;
		} else {
			return resp.getRoles().get(0).getId();
		}
	} 
	
	private String getProjectID(String token,HttpCon con,String name) throws Exception {
		StringBuffer b = new StringBuffer();
		b.append(this.url).append("/projects?name=").append(URLEncoder.encode(name, "UTF-8"));
		String json = this.callWS(token, con, b.toString());
		Gson gson = new Gson();
		ProjectsResponse res = gson.fromJson(json, ProjectsResponse.class);
		if (res.getProjects().isEmpty()) {
			return null;
		} else {
			return res.getProjects().get(0).getId();
		}
	}
	
	private String getDomainID(String token,HttpCon con,String name) throws Exception {
		StringBuffer b = new StringBuffer();
		b.append(this.url).append("/domains?name=").append(URLEncoder.encode(name, "UTF-8"));
		String json = this.callWS(token, con, b.toString());
		Gson gson = new Gson();
		DomainsResponse resp = gson.fromJson(json, DomainsResponse.class);
		if (resp.getDomains().isEmpty()) {
			return null;
		} else {
			return resp.getDomains().get(0).getId();
		}
	}
	
	public List<Map<Object,Object>> listDomains() throws ProvisioningException {
		HttpCon con = null;
		try {
			con = this.createClient();
			KSToken token = this.getToken(con);
			
			StringBuffer b = new StringBuffer();
			b.append(this.url).append("/domains?enabled");
			String json = this.callWS(token.getAuthToken(), con, b.toString());
			
			GsonBuilder builder = new GsonBuilder();
			Object o = builder.create().fromJson(json, Object.class);
			
			List<Map<Object,Object>> roles = (List<Map<Object,Object>>) ((Map<Object,Object>) o).get("domains");
			
			return roles;
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not work with keystone",e);
		} finally {
			if (con != null) {
				con.getBcm().shutdown();
			}
		}
	}
	
	public List<Map<Object,Object>> listProjects() throws ProvisioningException {
		HttpCon con = null;
		try {
			con = this.createClient();
			KSToken token = this.getToken(con);
			
			StringBuffer b = new StringBuffer();
			b.append(this.url).append("/projects?enabled");
			String json = this.callWS(token.getAuthToken(), con, b.toString());
			Gson gson = new Gson();
			
			GsonBuilder builder = new GsonBuilder();
			Object o = builder.create().fromJson(json, Object.class);
			
			List<Map<Object,Object>> roles = (List<Map<Object,Object>>) ((Map<Object,Object>) o).get("projects");
			
			return roles;
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not work with keystone",e);
		} finally {
			if (con != null) {
				con.getBcm().shutdown();
			}
		}
	}
	
	public List<Map<Object,Object>> listRoles() throws ProvisioningException {
		HttpCon con = null;
		try {
			con = this.createClient();
			KSToken token = this.getToken(con);
			
			StringBuffer b = new StringBuffer();
			b.append(this.url).append("/roles");
			String json = this.callWS(token.getAuthToken(), con, b.toString());
			GsonBuilder builder = new GsonBuilder();
			Object o = builder.create().fromJson(json, Object.class);
			
			List<Map<Object,Object>> roles = (List<Map<Object,Object>>) ((Map<Object,Object>) o).get("roles");
			
			return roles;
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not work with keystone",e);
		} finally {
			if (con != null) {
				con.getBcm().shutdown();
			}
		}
	}
	
	public List<KSDomain> listDomainObjs() throws ProvisioningException {
		HttpCon con = null;
		try {
			con = this.createClient();
			KSToken token = this.getToken(con);
			
			StringBuffer b = new StringBuffer();
			b.append(this.url).append("/domains?enabled");
			String json = this.callWS(token.getAuthToken(), con, b.toString());
			
			Gson gson = new Gson();
			return gson.fromJson(json, DomainsResponse.class).getDomains();
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not work with keystone",e);
		} finally {
			if (con != null) {
				con.getBcm().shutdown();
			}
		}
	}
	
	public List<Project> listProjectObjs() throws ProvisioningException {
		HttpCon con = null;
		try {
			con = this.createClient();
			KSToken token = this.getToken(con);
			
			StringBuffer b = new StringBuffer();
			b.append(this.url).append("/projects?enabled");
			String json = this.callWS(token.getAuthToken(), con, b.toString());
			Gson gson = new Gson();
			
			return gson.fromJson(json, ProjectsResponse.class).getProjects();
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not work with keystone",e);
		} finally {
			if (con != null) {
				con.getBcm().shutdown();
			}
		}
	}
	
	public List<KSRole> listRoleObjs() throws ProvisioningException {
		HttpCon con = null;
		try {
			con = this.createClient();
			KSToken token = this.getToken(con);
			
			StringBuffer b = new StringBuffer();
			b.append(this.url).append("/roles");
			String json = this.callWS(token.getAuthToken(), con, b.toString());
			Gson gson = new Gson();
			
			return gson.fromJson(json, RoleResponse.class).getRoles();
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not work with keystone",e);
		} finally {
			if (con != null) {
				con.getBcm().shutdown();
			}
		}
	}
}
