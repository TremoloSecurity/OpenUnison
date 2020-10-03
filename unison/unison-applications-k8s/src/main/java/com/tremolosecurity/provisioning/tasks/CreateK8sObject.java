/*
 * Copyright 2017, 2020 Tremolo Security, Inc.
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
 */

package com.tremolosecurity.provisioning.tasks;

import com.tremolosecurity.provisioning.core.*;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;

import org.apache.http.client.ClientProtocolException;
import org.apache.logging.log4j.Logger;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.yaml.snakeyaml.Yaml;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

public class CreateK8sObject implements CustomTask {
    static Logger logger = org.apache.logging.log4j.LogManager.getLogger(CreateK8sObject.class.getName());

    String template;
    String targetName;
    String kind;
    String url;
    String label;
    boolean doPost;
    
    boolean writeToSecret;
    String secretName;
    String path;
    String secretNamespace;
    boolean yaml;
    
    transient WorkflowTask task;

    @Override
    public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
        this.targetName = params.get("targetName").getValues().get(0);
        this.template = params.get("template").getValues().get(0);
        this.kind = params.get("kind").getValues().get(0);
        this.url = params.get("url").getValues().get(0);
        this.label = "kubernetes-" + this.kind.toLowerCase();

        this.doPost = params.get("doPost") == null || params.get("doPost").getValues().get(0).equalsIgnoreCase("true"); 
        
        this.writeToSecret = false;
        
        if (params.get("writeToSecret") != null) {
        	this.writeToSecret = params.get("writeToSecret").getValues().get(0).equalsIgnoreCase("true");
        	if (this.writeToSecret) {
	        	this.secretName = params.get("secretName").getValues().get(0);
	        	this.path = params.get("path").getValues().get(0);
	        	this.secretNamespace = params.get("secretNamespace").getValues().get(0);
        	}
        }
        
        this.yaml = params.get("srcType") != null && params.get("srcType").getValues().get(0).equalsIgnoreCase("yaml");
        
        this.task = task;

    }

    @Override
    public void reInit(WorkflowTask task) throws ProvisioningException {
        this.task = task;

    }

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
        String localTemplateJSON = "";

        HttpCon con = null;
        OpenShiftTarget os = (OpenShiftTarget) task.getConfigManager().getProvisioningEngine().getTarget(this.targetName).getProvider();
        try {
            String token = os.getAuthToken();
            con = os.createClient();
            
            if (this.yaml) {
    			Yaml yaml = new Yaml();
    			Map<String,Object> map= (Map<String, Object>) yaml.load(new ByteArrayInputStream(localTemplate.getBytes("UTF-8")));
    			JSONObject jsonObject=new JSONObject(map);
    			localTemplateJSON = jsonObject.toJSONString();
    		}
            
            
            if (this.writeToSecret) {
            	if (! os.isObjectExists(token, con, localURL,localTemplateJSON)) {
            		String localPath = task.renderTemplate(this.path, request);
            		String dirName;
            		String fileName;
            		int lastSlash = localPath.lastIndexOf('/');
            		if (lastSlash == -1) {
            			dirName = "";
            			fileName = localPath;
            		} else {
            			dirName = localPath.substring(0,lastSlash);
            			fileName = localPath.substring(lastSlash + 1);
            		}
            		
            		JSONObject fileInfo = new JSONObject();
            		fileInfo.put("fileName",fileName);
            		fileInfo.put("dirName",dirName);
            		fileInfo.put("data",Base64.getEncoder().encodeToString(localTemplate.getBytes("UTF-8")));
            		
            		
            		
            		
            		
            		JSONObject patch = new JSONObject();
            		JSONObject data = new JSONObject();
            		patch.put("data",data);
            		data.put(UUID.randomUUID().toString().toLowerCase(), Base64.getEncoder().encodeToString(fileInfo.toString().getBytes("UTF-8")));
            		
            		String patchJson = patch.toString();
            		
            		logger.info(patchJson);
            		
            		String localNamespace = task.renderTemplate(this.secretNamespace, request);
            		String localSecretName = task.renderTemplate(this.secretName, request);
            		
            		String secretUrl = "/api/v1/namespaces/" + localNamespace + "/secrets/" + localSecretName;
            		
            		String respJSON = os.callWSPatchJson(token, con, secretUrl, patchJson);

                    //if (logger.isDebugEnabled()) {
                        logger.info("Response for patching secret : '" + respJSON + "'");
                    //}

                    JSONParser parser = new JSONParser();
                    JSONObject resp = (JSONObject) parser.parse(respJSON);
                    String kind = (String) resp.get("kind");
                    String projectName = (String) ((JSONObject) resp.get("metadata")).get("name");


                    if (! kind.equalsIgnoreCase("Secret")) {
                        throw new ProvisioningException("Could not patch " + kind + "  '" + respJSON + "'" );
                    } else {
                    	this.task.getConfigManager().getProvisioningEngine().logAction(this.targetName,true, ProvisioningUtil.ActionType.Add,  approvalID, this.task.getWorkflow(), label, projectName);
                    }
            	}
            	
            } else {
            	writeToAPIServer(localTemplateJSON, approvalID, localURL, con, os, token);
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

	private void writeToAPIServer(String localTemplate, int approvalID, String localURL, HttpCon con,
			OpenShiftTarget os, String token)
			throws IOException, ClientProtocolException, ProvisioningException, ParseException {
		
		
		
		if (this.doPost) {
		    if (! os.isObjectExists(token, con, localURL,localTemplate)) {

		        String respJSON = os.callWSPost(token, con, localURL, localTemplate);

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
		            this.task.getConfigManager().getProvisioningEngine().logAction(this.targetName,true, ProvisioningUtil.ActionType.Add,  approvalID, this.task.getWorkflow(), label, projectName);
		        }
		    }
		} else {
			String respJSON = os.callWSPut(token, con, localURL, localTemplate);
			
		    if (logger.isDebugEnabled()) {
		        logger.debug("Response for putting object : '" + respJSON + "'");
		    }

		    JSONParser parser = new JSONParser();
		    JSONObject resp = (JSONObject) parser.parse(respJSON);
		    String kind = (String) resp.get("kind");
		    String projectName = (String) ((JSONObject) resp.get("metadata")).get("name");


		    if (! kind.equalsIgnoreCase(this.kind)) {
		        throw new ProvisioningException("Could not create " + kind + " with json '" + localTemplate + "' - '" + respJSON + "'" );
		    } else {
		        this.task.getConfigManager().getProvisioningEngine().logAction(this.targetName,true, ProvisioningUtil.ActionType.Replace,  approvalID, this.task.getWorkflow(), label, projectName);
		    }
		}
	}
}
