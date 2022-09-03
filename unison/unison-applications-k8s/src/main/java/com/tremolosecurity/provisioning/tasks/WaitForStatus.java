/*******************************************************************************
 * Copyright 2022 Tremolo Security, Inc.
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

package com.tremolosecurity.provisioning.tasks;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.crypto.Cipher;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import com.cedarsoftware.util.io.JsonWriter;
import com.google.gson.Gson;
import com.tremolosecurity.json.Token;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.ProvisioningUtil;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.tasks.dataobj.WaitForState;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;

import net.bytebuddy.asm.Advice.This;

public class WaitForStatus implements CustomTask {
	
	String uuid;

	transient WorkflowTask task;
	
	String holdingTarget;
	String target;
	String uri;
	Map<String,String> conditions;
	String label;
	String namespace;
	
	
	
	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
		this.uuid = UUID.randomUUID().toString();
		this.task = task;
		this.conditions = new HashMap<String,String>();
		
		this.holdingTarget = params.get("holdingTarget").getValues().get(0);
		this.target = params.get("target").getValues().get(0);
		this.uri = params.get("uri").getValues().get(0);
		this.label = params.get("label").getValues().get(0);
		this.namespace = params.get("namespace").getValues().get(0);
		
		for (String condition : params.get("conditions").getValues()) {
			String jsonPath = condition.substring(0,condition.lastIndexOf('='));
			String value = condition.substring(condition.lastIndexOf('=') + 1);
			this.conditions.put(jsonPath, value);
		}
		
		
		
		
	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
		this.task = task;

	}

	
	private boolean runChildTasks(User user, Map<String, Object> request) throws ProvisioningException {
		this.task.setOnHold(false);
		HashMap<String,Object> nrequest = new HashMap<String,Object>();
		nrequest.putAll(request);
		
		
		return this.task.restartChildren();
		
	}
	
	@Override
	public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {
		
		if (task.isOnHold()) {
			this.task.setOnHold(false);
			
			return this.task.restartTasks();
		} else {
			
			this.task.setOnHold(true);
		
			WaitForState state = new WaitForState();
			state.setUuid(this.uuid);
			state.setUri(task.renderTemplate(this.uri, request));
			state.setTarget(task.renderTemplate(this.target, request));
			
			for (String jsonPath : this.conditions.keySet()) {
				state.getConditions().put(task.renderTemplate(jsonPath, request), task.renderTemplate(this.conditions.get(jsonPath), request));
			}
			
			String json = "";
			synchronized (this.task.getWorkflow()) {
				json = JsonWriter.objectToJson(this.task.getWorkflow());
			}
			
			try {
				state.setBase64Workflow(java.util.Base64.getEncoder().encodeToString(json.getBytes("UTF-8")));
			} catch (UnsupportedEncodingException e) {
				throw new ProvisioningException("Could not encode workflow",e);
			}
			
			json = JsonWriter.objectToJson(state);
			String encodedToken = "";
			try {
				Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
				cipher.init(Cipher.ENCRYPT_MODE, task.getConfigManager().getSecretKey(task.getConfigManager().getCfg().getProvisioning().getApprovalDB().getEncryptionKey()));
				
				
				byte[] encJson = cipher.doFinal(json.getBytes("UTF-8"));
				String base64d = new String(org.bouncycastle.util.encoders.Base64.encode(encJson));
				
				Token token = new Token();
				token.setEncryptedRequest(base64d);
				token.setIv(new String(org.bouncycastle.util.encoders.Base64.encode(cipher.getIV())));
				Gson gson = new Gson();
				encodedToken = java.util.Base64.getEncoder().encodeToString(gson.toJson(token).getBytes("UTF-8"));
			} catch (Throwable t) {
				throw new ProvisioningException("Could not encrypt state",t);
			}
			
			JSONObject waitForObj = new JSONObject();
			waitForObj.put("kind", "WaitForState");
			waitForObj.put("apiVersion","openunison.tremolo.io/v1");
			
			JSONObject metadata = new JSONObject();
			waitForObj.put("metadata", metadata);
			metadata.put("name",this.task.renderTemplate(this.label, request) + "-" + this.task.getWorkflow().getId() + "-x");
			metadata.put("namespace", this.namespace);
			
			JSONObject spec = new JSONObject();
			waitForObj.put("spec", spec);
			spec.put("state", encodedToken);
			
			OpenShiftTarget k8s = (OpenShiftTarget) this.task.getConfigManager().getProvisioningEngine().getTarget(this.holdingTarget).getProvider();
			HttpCon con = null;
			try {
				con = k8s.createClient();
				String resp = k8s.callWSPost(k8s.getAuthToken(), con, "/apis/openunison.tremolo.io/v1/namespaces/" + this.namespace + "/waitforstates", waitForObj.toString());
				JSONObject respObj = (JSONObject) new JSONParser().parse(resp);
				if (! respObj.get("kind").equals("WaitForState")) {
					throw new ProvisioningException("Could not store state:" + resp);
				}
			} catch (Exception e) {
				throw new ProvisioningException("Could not store state",e);
			} finally {
				if (con != null) {
					try {
						con.getHttp().close();
					} catch (IOException e) {
						
					}
					
					con.getBcm().close();
					
				}
			}
			
			int approvalID = 0;
	        if (request.containsKey("APPROVAL_ID")) {
	            approvalID = (Integer) request.get("APPROVAL_ID");
	        }

	        Workflow workflow = (Workflow) request.get("WORKFLOW");
	        
	        this.task.getConfigManager().getProvisioningEngine().logAction(this.holdingTarget,true, ProvisioningUtil.ActionType.Add,  approvalID, this.task.getWorkflow(), "kubernetes-waitforstate", (String) metadata.get("name"));
			
			
			
			return false;
		}
	}

	public String getUuid() {
		return uuid;
	}
	
	
	

}
