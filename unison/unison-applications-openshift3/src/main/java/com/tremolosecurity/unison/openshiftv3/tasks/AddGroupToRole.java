/*******************************************************************************
 * Copyright 2017 Tremolo Security, Inc.
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
package com.tremolosecurity.unison.openshiftv3.tasks;

import java.util.Map;

import org.apache.logging.log4j.Logger;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import com.google.gson.Gson;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;
import com.tremolosecurity.unison.openshiftv3.model.Response;

public class AddGroupToRole implements CustomTask {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(AddGroupToRole.class);
	
	String projectName;
	String groupName;
	String roleName;
	String targetName;
	
	double openShiftVersion;

	transient WorkflowTask task;

	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
		this.projectName = params.get("projectName").getValues().get(0);
		this.groupName = params.get("groupName").getValues().get(0);
		this.roleName = params.get("roleName").getValues().get(0);
		this.targetName = params.get("targetName").getValues().get(0);
		
		if (params.get("version") != null) {
			String val = params.get("version").getValues().get(0);
			this.openShiftVersion = Double.parseDouble(val);
			if (this.openShiftVersion < 3.6 || this.openShiftVersion > 3.7) {
				throw new ProvisioningException("OpenShift version must be between 3.6 and 3.7");
			}
		} else {
			this.openShiftVersion = 3.7;
		}

		this.task = task;

	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
		this.task = task;

	}

	@Override
	public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");

		String localProjectName = task.renderTemplate(projectName, request);
		String localGroupName = task.renderTemplate(groupName, request);
		String localPolicyName = task.renderTemplate(roleName, request);
		
		
		HttpCon con = null;
		OpenShiftTarget os = (OpenShiftTarget) task.getConfigManager().getProvisioningEngine().getTarget("openshift").getProvider();
		try {
			String token = os.getAuthToken();
			con = os.createClient();
			
			if (this.openShiftVersion == 3.6) {
				addTo36Role(os,token,con,localProjectName,localPolicyName,localGroupName,approvalID);
			} else {
				addTo37Role(os,token,con,localProjectName,localPolicyName,localGroupName,approvalID);
			}
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not add group to role",e);
		} finally {
			if (con != null) {
				con.getBcm().close();
			}
		}
		
		
		
		
		
		return true;
	}


	private void addTo37Role(OpenShiftTarget os, String token, HttpCon con, String localProjectName,
			String localPolicyName, String localGroupName, int approvalID) throws Exception {

		String roleBindingUri = new StringBuilder().append("/apis/rbac.authorization.k8s.io/v1beta1/namespaces/").append(localProjectName).append("/rolebindings/").append(localPolicyName).toString();
		String json = os.callWS(token, con, roleBindingUri);
			
		if (logger.isDebugEnabled()) {
			logger.debug("Policy binding : '" + json + "'");
		}

		JSONParser parser = new JSONParser();
		JSONObject rb = (JSONObject) parser.parse(json);
		if (rb.get("status") != null && rb.get("status").equals("Failure")) {
			throw new ProvisioningException("Role binding : '" + localPolicyName + "' does not exist");
		}

		JSONArray subjects = (JSONArray) rb.get("subjects");
		if (subjects != null) {
			for (Object o : subjects) {
				JSONObject jo = (JSONObject) o;
				if (jo.get("kind").equals("Group") && jo.get("name").equals(localGroupName)) {
					logger.warn(localGroupName + " already in policy " + localPolicyName + " on project " + localProjectName);
					return;
				}
			}
		} else {
			subjects = new JSONArray();
			rb.put("subjects", subjects);
		}

		JSONObject binding = new JSONObject();
		binding.put("kind","Group");
		binding.put("apiGroup", "rbac.authorization.k8s.io");
		binding.put("name", localGroupName);

		subjects.add(binding);

		String jsonResp = os.callWSPut(token, con, roleBindingUri, rb.toJSONString());
		Gson gson = new Gson();
		Response resp = gson.fromJson(jsonResp, Response.class);
		if (resp.getStatus() != null) {
			throw new ProvisioningException("Could not add '" + localGroupName + "' to '" + localPolicyName + "' in project '" + localProjectName + "' - " + jsonResp);
		} else {
			this.task.getConfigManager().getProvisioningEngine().logAction(this.targetName,true, ActionType.Add,  approvalID, this.task.getWorkflow(), "openshift-project.role.group", new StringBuilder().append(localProjectName).append('.').append(localPolicyName).append('.').append(localGroupName).toString());
		}


	}

	private void addTo36Role(OpenShiftTarget os,String token,HttpCon con,String localProjectName,String localPolicyName,String localGroupName,int approvalID) throws Exception {
		String roleBindingUri = new StringBuilder().append("/oapi/v1/namespaces/").append(localProjectName).append("/policybindings").toString();
			String json = os.callWS(token, con, roleBindingUri);
			
			if (logger.isDebugEnabled()) {
				logger.debug("All policy bindings : '" + json + "'");
			}
			
			JSONParser parser = new JSONParser();
			JSONObject pbl = (JSONObject) parser.parse(json);
			JSONArray items = (JSONArray) pbl.get("items");
			JSONArray rb = (JSONArray) ((JSONObject )items.get(0)).get("roleBindings");
			
			JSONObject foundRoleBinding = null;
			
			
			boolean foundInGroupName = false;
			boolean foundInSubjects = false;
			boolean foundPolicy = false;
			
			for (Object o : rb) {
				
				JSONObject binding = (JSONObject) o;
				
				
				if (binding.get("name").equals(localPolicyName)) {
					foundPolicy = true;
					JSONObject rbx = (JSONObject) binding.get("roleBinding");
					foundRoleBinding = rbx;
					JSONArray groupNames = (JSONArray) rbx.get("groupNames");
					if (groupNames != null) {
						for (Object o1 : groupNames) {
							String groupName = (String) o1;
							
							if (groupName.equalsIgnoreCase(localGroupName)) {
								foundInGroupName = true;
							}
						}
					}
					
					JSONArray subjects = (JSONArray) rbx.get("subjects");
					if (subjects != null) {
						for (Object o1 : subjects) {
							JSONObject subj = (JSONObject) o1;
							if (subj.get("kind").equals("group") && subj.get("name").equals(localGroupName)) {
								foundInSubjects = true;
							}
							
							
						}
					}
				}
			}
			
			if (foundInGroupName || foundInSubjects) {
				logger.warn(localGroupName + " already in policy " + localPolicyName + " on project " + localProjectName);
			} else {
				
				
				
				if (foundRoleBinding != null) {
					JSONArray groupNames = (JSONArray) foundRoleBinding.get("groupNames");
					
					if (groupNames == null) {
						groupNames = new JSONArray();
						foundRoleBinding.put("groupNames", groupNames);
					}
					
					groupNames.add(localGroupName);
					
					JSONArray subjects = (JSONArray) foundRoleBinding.get("subjects");
					
					if (subjects == null) {
						subjects = new JSONArray();
						foundRoleBinding.put("subjects", subjects);
					}
					
					JSONObject subject = new JSONObject();
					
					subject.put("kind", "Group");
					subject.put("name", localGroupName);
					
					subjects.add(subject);
					
					foundRoleBinding.put("kind", "RoleBinding");
					foundRoleBinding.put("apiVersion", "v1");
					
					if (logger.isDebugEnabled()) {
						logger.debug("new policy : '" + foundRoleBinding + "'");
					}
					
					String saveURI = new StringBuilder().append("/oapi/v1/namespaces/").append(localProjectName).append("/rolebindings/").append(localPolicyName).toString();
					String jsonResp = os.callWSPut(token, con, saveURI, foundRoleBinding.toJSONString());
					Gson gson = new Gson();
					Response resp = gson.fromJson(jsonResp, Response.class);
					if (! resp.getKind().equals("RoleBinding")) {
						throw new ProvisioningException("Could not add '" + localGroupName + "' to '" + localPolicyName + "' in project '" + localProjectName + "' - " + jsonResp);
					} else {
						this.task.getConfigManager().getProvisioningEngine().logAction(this.targetName,true, ActionType.Add,  approvalID, this.task.getWorkflow(), "openshift-project.role.group", new StringBuilder().append(localProjectName).append('.').append(localPolicyName).append('.').append(localGroupName).toString());
					}
					
				} else {
					foundRoleBinding = new JSONObject();
					
					foundRoleBinding.put("kind", "RoleBinding");
					foundRoleBinding.put("apiVersion", "v1");
					
					JSONObject metadata = new JSONObject();
					metadata.put("name", localPolicyName);
					metadata.put("namespace", localProjectName);
					foundRoleBinding.put("metadata", metadata);
					
					JSONArray groupNames = new JSONArray();
					foundRoleBinding.put("groupNames", groupNames);
					groupNames.add(localGroupName);
					
					JSONArray subjects = new JSONArray();
					foundRoleBinding.put("subjects", subjects);
					
					JSONObject subject = new JSONObject();
					
					subject.put("kind", "Group");
					subject.put("name", localGroupName);
					
					subjects.add(subject);
					
					JSONObject roleRef = new JSONObject();
					roleRef.put("name", localPolicyName);
					foundRoleBinding.put("roleRef", roleRef);
					
					String saveURI = new StringBuilder().append("/oapi/v1/namespaces/").append(localProjectName).append("/rolebindings").toString();
					String jsonResp = os.callWSPost(token, con, saveURI, foundRoleBinding.toJSONString());
					Gson gson = new Gson();
					if (logger.isDebugEnabled()) {
						logger.debug("response json  - " + jsonResp);
					}
					Response resp = gson.fromJson(jsonResp, Response.class);
					
					if (! resp.getKind().equals("RoleBinding")) {
						throw new ProvisioningException("Could not add '" + localGroupName + "' to '" + localPolicyName + "' in project '" + localProjectName + "' - " + resp.getStatus());
					} else {
						this.task.getConfigManager().getProvisioningEngine().logAction(this.targetName,true, ActionType.Add,  approvalID, this.task.getWorkflow(), "openshift-project.role.group", new StringBuilder().append(localProjectName).append('.').append(localPolicyName).append('.').append(localGroupName).toString());
					}
				}
				
				
				
			}

	}

}
