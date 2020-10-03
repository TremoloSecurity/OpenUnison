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
package com.tremolosecurity.provisioning.tasks;

import java.util.Map;

import org.apache.logging.log4j.Logger;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.ProvisioningUtil;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;

public class DeleteK8sObject implements CustomTask {
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(DeleteK8sObject.class.getName());
	
	String targetName;
	String url;
	String kind;
    String label;
    
    transient WorkflowTask task;

	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
		this.targetName = params.get("targetName").getValues().get(0);
		this.kind = params.get("kind").getValues().get(0);
        this.url = params.get("url").getValues().get(0);
        this.label = "kubernetes-" + this.kind.toLowerCase();
        
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

        String localURL = task.renderTemplate(this.url,request);
        
        HttpCon con = null;
        OpenShiftTarget os = (OpenShiftTarget) task.getConfigManager().getProvisioningEngine().getTarget(this.targetName).getProvider();
        try {
            String token = os.getAuthToken();
            con = os.createClient();
            String respJSON = os.callWSDelete(token, con, localURL);
            
            //if (logger.isDebugEnabled()) {
		        logger.info("Response for deleting object : '" + respJSON + "'");
		    //}


		    
		    JSONParser parser = new JSONParser();
		    JSONObject resp = (JSONObject) parser.parse(respJSON);
		    String kind = (String) resp.get("kind");
		    String projectName = (String) ((JSONObject) resp.get("metadata")).get("name");
		    
		    if (! kind.equalsIgnoreCase(this.kind)) {
		        throw new ProvisioningException("Could not delete " + kind + " with url '" + localURL + "' - '" + respJSON + "'" );
		    } else {
		        this.task.getConfigManager().getProvisioningEngine().logAction(this.targetName,true, ProvisioningUtil.ActionType.Delete,  approvalID, this.task.getWorkflow(), label, projectName);
		    }
        } catch (Exception e) {
            throw new ProvisioningException("Could not delete " + kind + " - " + localURL,e);
        } finally {
            if (con != null) {
                con.getBcm().close();
            }
        }
        return true;
	}

}
