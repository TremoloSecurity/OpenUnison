//    Copyright 2018 Tremolo Security, Inc.
// 
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
// 
//        http://www.apache.org/licenses/LICENSE-2.0
// 
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

package com.tremolosecurity.provisioning.tasks;

import java.io.IOException;
import java.util.Map;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;

import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicHeader;
import org.apache.http.util.EntityUtils;
import org.apache.logging.log4j.Logger;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

/**
 * PatchK8sObject
 */
public class PatchK8sObject implements CustomTask {

    static Logger logger = org.apache.logging.log4j.LogManager.getLogger(PatchK8sObject.class.getName());

    String template;
    String targetName;
    String kind;
    String url;
    String label;
    
    

    transient WorkflowTask task;

    @Override
    public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {
        String localTemplate = task.renderTemplate(template, request);
        if (logger.isDebugEnabled()) {
            logger.debug("localTemplate : '" + localTemplate + "'");
        }

        int approvalID = 0;
        if (request.containsKey("APPROVAL_ID")) {
            approvalID = (Integer) request.get("APPROVAL_ID");
        }

        Workflow workflow = (Workflow) request.get("WORKFLOW");

        String localURL = task.renderTemplate(this.url,request);


        HttpCon con = null;
        
        String localTarget = task.renderTemplate(this.targetName, request);
        OpenShiftTarget os = (OpenShiftTarget) task.getConfigManager().getProvisioningEngine().getTarget(localTarget).getProvider();
        try {
            String token = os.getAuthToken();
            con = os.createClient();

            if (this.isObjectExists(os,token, con, localURL,localTemplate)) {

                String respJSON = os.callWSPatchJson(token, con, localURL, localTemplate);

                if (logger.isDebugEnabled()) {
                    logger.debug("Response for creating project : '" + respJSON + "'");
                }

                JSONParser parser = new JSONParser();
                JSONObject resp = (JSONObject) parser.parse(respJSON);
                String kind = (String) resp.get("kind");
                String projectName = (String) ((JSONObject) resp.get("metadata")).get("name");


                if (! kind.equalsIgnoreCase(this.kind)) {
                    throw new ProvisioningException("Could not create " + kind + " with json '" + localTemplate + "' - '" + respJSON + "'" );
                } else {
                    this.task.getConfigManager().getProvisioningEngine().logAction(localTarget,true, ActionType.Replace,  approvalID, this.task.getWorkflow(), label, projectName);
                }
            } else {
                throw new ProvisioningException("Object '" + localURL + "' does not exist");
            }
        } catch (Exception e) {
            throw new ProvisioningException("Could not create " + kind,e);
        } finally {
            if (con != null) {
                con.getBcm().close();
            }
        }
        return true;
    }
    
    

    @Override
    public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
        this.targetName = params.get("targetName").getValues().get(0);
        this.template = params.get("template").getValues().get(0);
        this.kind = params.get("kind").getValues().get(0);
        this.url = params.get("url").getValues().get(0);
        this.label = "kubernetes-" + this.kind.toLowerCase();
        
        this.task = task;

	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
        this.task = task;
        
    }
    
    private boolean isObjectExists(OpenShiftTarget os,String token, HttpCon con,String uri,String json) throws IOException, ClientProtocolException,ProvisioningException, ParseException {
		
		JSONParser parser = new JSONParser();
		JSONObject root = (JSONObject) parser.parse(json);
		JSONObject metadata = (JSONObject) root.get("metadata");

		

		
		
		
		
		
		
		
		json = os.callWS(token, con, uri);
		

		root = (JSONObject) parser.parse(json);
		if (root.containsKey("kind") && root.get("kind").equals("Status") && ((Long) root.get("code")) == 404) {
			return false;
		} else {
			return true;
		}
			

		
		
	}

    
}