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
package com.tremolosecurity.argocd.tasks;

import java.util.Map;

import org.apache.logging.log4j.Logger;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;

public class AddtoRBAC implements CustomTask {
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(AddtoRBAC.class.getName());
	
	String toAdd;
	String k8sTarget;
	
	transient WorkflowTask task;

	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
		this.task = task;
		
		this.toAdd = params.get("toAdd").getValues().get(0);
		this.k8sTarget = params.get("k8sTarget").getValues().get(0);

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
        
        HttpCon con = null;
        OpenShiftTarget os = (OpenShiftTarget) task.getConfigManager().getProvisioningEngine().getTarget(this.k8sTarget).getProvider();
        try {
            String token = os.getAuthToken();
            con = os.createClient();
            
            String rbacCfgMapJson = os.callWS(token, con, "/api/v1/namespaces/argocd/configmaps/argocd-rbac-cm");
            JSONObject rbacCfgMap = (JSONObject) new JSONParser().parse(rbacCfgMapJson);
            JSONObject data = (JSONObject) rbacCfgMap.get("data");
            
            StringBuilder newRbac = new StringBuilder();
            
            if (data != null) {
            	newRbac.append(data.get("policy.csv")).append('\n');
            }
            
            String policiesToAdd = this.task.renderTemplate(this.toAdd, request);
            
            newRbac.append(policiesToAdd);
            
            JSONObject patch = new JSONObject();
            JSONObject pdata = new JSONObject();
            patch.put("data",pdata);
            pdata.put("policy.csv",newRbac.toString());
            
            String json = patch.toString();
            
            String respJSON = os.callWSPatchJson(token, con, "/api/v1/namespaces/argocd/configmaps/argocd-rbac-cm", json);

            if (logger.isDebugEnabled()) {
                logger.debug("Response for creating project : '" + respJSON + "'");
            }

            JSONParser parser = new JSONParser();
            JSONObject resp = (JSONObject) parser.parse(respJSON);
            String kind = (String) resp.get("kind");
            String projectName = (String) ((JSONObject) resp.get("metadata")).get("name");


            if (! kind.equalsIgnoreCase("ConfigMap")) {
                throw new ProvisioningException("Could not update the ArgoCD RBAC ConfigMap - '" + respJSON + "'" );
            } else {
                this.task.getConfigManager().getProvisioningEngine().logAction(this.k8sTarget,true, ActionType.Replace,  approvalID, this.task.getWorkflow(), "argocd-rbac-cm", projectName);
            }
            
        } catch (Exception e) {
            throw new ProvisioningException("Could not update argocd rbac",e);
        } finally {
            if (con != null) {
                con.getBcm().close();
            }
        }
		
		return true;
	}

}
