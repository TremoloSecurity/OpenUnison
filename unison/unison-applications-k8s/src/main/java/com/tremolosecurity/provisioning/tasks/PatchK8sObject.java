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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.provisioning.tasks.dataobj.GitFile;
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
    
    String writeToRequestConfig;
    private String requestAttribute;
    String path;
    
    
    

    transient WorkflowTask task;

	private String patchType;
	private String patchContentType;

    @Override
    public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {
        doPatch(request,this.task,this.template,this.targetName,this.url,this.writeToRequestConfig,this.path,this.patchType,this.requestAttribute,this.kind,this.label,this.patchContentType);
        return true;
    }



	public static void doPatch(Map<String, Object> request, WorkflowTask task, String template,String targetName,String url,String writeToRequestConfig,String path,String patchType,String requestAttribute,String expKind,String label,String patchContentType) throws ProvisioningException {
		String localTemplate = task.renderTemplate(template, request);
        if (logger.isDebugEnabled()) {
            logger.debug("localTemplate : '" + localTemplate + "'");
        }

        int approvalID = 0;
        if (request.containsKey("APPROVAL_ID")) {
            approvalID = (Integer) request.get("APPROVAL_ID");
        }

        Workflow workflow = (Workflow) request.get("WORKFLOW");

        String localURL = task.renderTemplate(url,request);


        HttpCon con = null;
        
        String localTarget = task.renderTemplate(targetName, request);
        OpenShiftTarget os = (OpenShiftTarget) task.getConfigManager().getProvisioningEngine().getTarget(localTarget).getProvider();
        try {
            String token = os.getAuthToken();
            con = os.createClient();

            boolean writeToRequest = false;
            if (writeToRequestConfig != null) {
            	writeToRequest = task.renderTemplate(writeToRequestConfig, request).equalsIgnoreCase("true");
            }
            
            if (writeToRequest) {
            	logger.debug("Writing to secret");
    
        		String localPath = task.renderTemplate(path, request);
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
        		
        		
        		
        		
        		GitFile gitFile = new GitFile(fileName,dirName,false,false);
        		gitFile.setData(localTemplate);
        		gitFile.setPatch(true);
        		gitFile.setPatchType(patchType);
        		
        		List<GitFile> gitFiles = (List<GitFile>) request.get(requestAttribute);
        		
        		if (gitFiles == null) {
        			gitFiles = new ArrayList<GitFile>();
        			request.put(requestAttribute, gitFiles);
        			
        		}
        		
        		gitFiles.add(gitFile);
            		
            	
            	
            } else {
            	if (isObjectExists(os,token, con, localURL,localTemplate)) {

                    String respJSON = os.callWSPatchJson(token, con, localURL, localTemplate,patchContentType);

                    if (logger.isDebugEnabled()) {
                        logger.debug("Response for creating project : '" + respJSON + "'");
                    }

                    JSONParser parser = new JSONParser();
                    JSONObject resp = (JSONObject) parser.parse(respJSON);
                    String kind = (String) resp.get("kind");
                    String projectName = (String) ((JSONObject) resp.get("metadata")).get("name");


                    if (! kind.equalsIgnoreCase(expKind)) {
                        throw new ProvisioningException("Could not create " + kind + " with json '" + localTemplate + "' - '" + respJSON + "'" );
                    } else {
                        task.getConfigManager().getProvisioningEngine().logAction(localTarget,true, ActionType.Replace,  approvalID, task.getWorkflow(), label, projectName);
                    }
                } else {
                    throw new ProvisioningException("Object '" + localURL + "' does not exist");
                }
            }
            
            
            
        } catch (Exception e) {
            throw new ProvisioningException("Could not patch " + expKind,e);
        } finally {
            if (con != null) {
                con.getBcm().close();
            }
        }
	}
    
    

    @Override
    public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
        this.targetName = params.get("targetName").getValues().get(0);
        this.template = params.get("template").getValues().get(0);
        this.kind = params.get("kind").getValues().get(0);
        this.url = params.get("url").getValues().get(0);
        this.label = "kubernetes-" + this.kind.toLowerCase();
        
        this.task = task;
        
        this.writeToRequestConfig = "false";
        
        if (params.get("writeToRequest") != null) {
        	this.writeToRequestConfig = params.get("writeToRequest").getValues().get(0);
        	if (this.writeToRequestConfig != null) {
	        	if (params.get("requestAttribute") != null) this.requestAttribute = params.get("requestAttribute").getValues().get(0);
	        	if (params.get("path") != null ) this.path = params.get("path").getValues().get(0);
        	}
        }
        
        if (params.get("patchType") != null) {
        	this.patchType = params.get("patchType").getValues().get(0);
        } else {
        	this.patchType = "merge";
        }
        
        switch (this.patchType) {
        	case "strategic": this.patchContentType = "application/strategic-merge-patch+json"; break;
        	case "merge" : this.patchContentType = "application/merge-patch+json"; break;
        	case "json" : this.patchContentType = "application/json-patch+json"; break;
        	default: throw new ProvisioningException("Unknown patch type, one of strategic, merge, or json is required");
        }

	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
        this.task = task;
        
    }
    
    private static boolean isObjectExists(OpenShiftTarget os,String token, HttpCon con,String uri,String json) throws IOException, ClientProtocolException,ProvisioningException, ParseException {
		
		JSONParser parser = new JSONParser();
		JSONObject root = null;
		

		

		
		
		
		
		
		
		
		json = os.callWS(token, con, uri);
		

		root = (JSONObject) parser.parse(json);
		if (root.containsKey("kind") && root.get("kind").equals("Status") && ((Long) root.get("code")) == 404) {
			return false;
		} else {
			return true;
		}
			

		
		
	}

    
}