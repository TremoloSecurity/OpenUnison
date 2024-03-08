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
import com.tremolosecurity.provisioning.tasks.dataobj.GitFile;
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
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class CreateK8sObject implements CustomTask {
    static Logger logger = org.apache.logging.log4j.LogManager.getLogger(CreateK8sObject.class.getName());

    String template;
    String targetName;
    
    String label;
    boolean doPost;
    
    String writeToRequestConfig;
    String path;
    boolean yaml;
    
    transient WorkflowTask task;
    
    String homeCluster;

	private String requestAttribute;
	
	
	String patchTemplate;
	String patchType;
	String patchContentType;
    
    

    @Override
    public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
        this.targetName = params.get("targetName").getValues().get(0);
        this.template = params.get("template").getValues().get(0);
        
        
        this.label = "kubernetes-";

        this.doPost = params.get("doPost") == null || params.get("doPost").getValues().get(0).equalsIgnoreCase("true"); 
        
        
        
        this.writeToRequestConfig = "false";
        
        if (params.get("writeToRequest") != null) {
        	this.writeToRequestConfig = params.get("writeToRequest").getValues().get(0);
        	if (this.writeToRequestConfig != null) {
	        	if (params.get("requestAttribute") != null) this.requestAttribute = params.get("requestAttribute").getValues().get(0);
	        	if (params.get("path") != null ) this.path = params.get("path").getValues().get(0);
        	}
        }
        
        this.yaml = params.get("srcType") != null && params.get("srcType").getValues().get(0).equalsIgnoreCase("yaml");
        
       if (params.get("patchTemplate") != null) {
    	   this.patchTemplate = params.get("patchTemplate").getValues().get(0);
       } else {
    	   this.patchTemplate = null;
       }
        
        if (params.get("patchType") != null) {
        	this.patchType = params.get("patchType").getValues().get(0);
        } else {
        	this.patchType = "apply";
        }
        
        switch (this.patchType) {
        	case "strategic": this.patchContentType = "application/strategic-merge-patch+json"; break;
        	case "merge" : this.patchContentType = "application/merge-patch+json"; break;
        	case "json" : this.patchContentType = "application/json-patch+json"; break;
        	case "apply" : this.patchContentType = "application/apply-patch+yaml"; break;
        	default: throw new ProvisioningException("Unknown patch type, one of strategic, merge, or json is required");
        }
        
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

        String kind = "unknown";
        String localTemplateJSON = "";

        HttpCon con = null;
        String localTarget = task.renderTemplate(this.targetName, request);
        OpenShiftTarget os = (OpenShiftTarget) task.getConfigManager().getProvisioningEngine().getTarget(localTarget).getProvider();
        try {
            String token = os.getAuthToken();
            con = os.createClient();
            
            if (this.yaml) {
    			Yaml yaml = new Yaml();
    			Map<String,Object> map= (Map<String, Object>) yaml.load(new ByteArrayInputStream(localTemplate.getBytes("UTF-8")));
    			JSONObject jsonObject=new JSONObject(map);
    			localTemplateJSON = jsonObject.toJSONString();
    		} else {
    			localTemplateJSON = localTemplate;
    		}
            
            JSONObject objectRoot = (JSONObject) new JSONParser().parse(localTemplateJSON);
            
            JSONObject metadata = (JSONObject) objectRoot.get("metadata");
            
            String objectName = null;
            String nameSpace = null;
            if (metadata != null) {
            	objectName = (String) metadata.get("name");
            	nameSpace = (String) metadata.get("namespace");
            }
            kind = (String) objectRoot.get("kind");
            String apiGroup = (String) objectRoot.get("apiVersion");
            
            String localURL = null;
            
            if (nameSpace == null) {
            	localURL = os.getApis().getUri(apiGroup, kind);
            } else {
            	localURL = os.getApis().getUri(apiGroup, kind, nameSpace);
            }
            
            if (logger.isDebugEnabled()) {
            	logger.debug("Write To Request  : '" + this.writeToRequestConfig + "'");
            }
            
            boolean writeToRequest = false;
            if (this.writeToRequestConfig != null) {
            	writeToRequest = task.renderTemplate(this.writeToRequestConfig, request).equalsIgnoreCase("true");
            }
            
            
            
            
            if (writeToRequest) {
            	logger.debug("Writing to secret");
            	if (! os.isObjectExists(token, con, localURL,localTemplateJSON)) {
            		if (logger.isDebugEnabled()) {
            			logger.debug("Url '" + localURL + "' doesn't exist");
            		}
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
            		
            		GitFile gitFile = new GitFile(fileName,dirName,localTemplate);
            		
            		List<GitFile> gitFiles = (List<GitFile>) request.get(this.requestAttribute);
            		
            		if (gitFiles == null) {
            			gitFiles = new ArrayList<GitFile>();
            			request.put(this.requestAttribute, gitFiles);
            			
            		}
            		
            		gitFiles.add(gitFile);
            		
            	} else if (this.patchTemplate != null) {
            		
            		doPatch(objectName,request, task, this.patchTemplate, this.targetName, String.format("%s/%s",localURL,objectName), writeToRequestConfig, this.path, this.patchType, this.requestAttribute, kind, String.format("%s%s",this.label,kind), this.patchContentType,kind);
            	} else if (this.patchType != null && this.patchType.equals("apply")) {
            		doPatch(objectName,request, task, localTemplateJSON, this.targetName, String.format("%s/%s",localURL,objectName), writeToRequestConfig, this.path, this.patchType, this.requestAttribute, kind, String.format("%s%s",this.label,kind), this.patchContentType,kind);
            	}
            		
            	
            } else {
            	writeToAPIServer(localTemplateJSON, approvalID, localURL, con, os, token,localTarget,request,objectName,kind);
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
			OpenShiftTarget os, String token,String localTarget,Map<String, Object> request, String objectName,String kind)
			throws IOException, ClientProtocolException, ProvisioningException, ParseException {
		
		
		
		if (this.doPost) {
			JSONParser parser = new JSONParser();
			String respJSON = os.callWS(token, con, String.format("%s/%s",localURL,objectName));
			
			JSONObject resp = (JSONObject) parser.parse(respJSON);
			
			boolean objectFound = false;
			
			
			if (resp.get("kind") != null) {
			
				if (resp.get("kind").equals("Status")) {
					if (((Long)resp.get("code")) == 404L) {
						objectFound = false;
					} else {
						logger.warn(String.format("Unknown response to %s, %s", localURL,respJSON));
						throw new ProvisioningException(String.format("Unknown response to %s, %s", localURL,respJSON));
					}
				} else {
					objectFound = true;
					JSONObject metadata = (JSONObject) resp.get("metadata");
					if (metadata == null) {
						logger.warn(String.format("No metadata from response to %s, %s", localURL,respJSON));
						throw new ProvisioningException(String.format("No metadata from response to %s, %s", localURL,respJSON));
					} else {
						String resourceVersion = (String) metadata.get("resourceVersion");
						JSONObject tmpObj = (JSONObject) parser.parse(localTemplate);
						JSONObject tmpMetaData = (JSONObject) tmpObj.get("metadata");
						if (tmpMetaData == null) {
							logger.warn(String.format("Object for %s has no metadata", localURL));
							throw new ProvisioningException(String.format("Object for %s has no metadata", localURL));
						}
						
						tmpMetaData.put("resourceVersion", resourceVersion);
						localTemplate = tmpObj.toString();
					}
				}
			
			} else {
				logger.warn(String.format("Unknown response to %s, %s", localURL,respJSON));
				throw new ProvisioningException(String.format("Unknown response to %s, %s", localURL,respJSON));
			}
			
		    if (! objectFound) {

		        respJSON = os.callWSPost(token, con, localURL, localTemplate);

		        if (logger.isDebugEnabled()) {
		            logger.debug("Response for creating project : '" + respJSON + "'");
		        }

		        
		        resp = (JSONObject) parser.parse(respJSON);
		        String localkind = (String) resp.get("kind");
		        String projectName = (String) ((JSONObject) resp.get("metadata")).get("name");


		        if (! localkind.equalsIgnoreCase(kind)) {
		            throw new ProvisioningException("Could not create " + kind + " with json '" + localTemplate + "' - '" + respJSON + "'" );
		        } else {
		            this.task.getConfigManager().getProvisioningEngine().logAction(localTarget,true, ProvisioningUtil.ActionType.Add,  approvalID, this.task.getWorkflow(), String.format("%s%s",this.label,kind), projectName);
		        }
		    } else if (this.patchTemplate != null) {
		    	doPatch(objectName,request, task, this.patchTemplate, this.targetName, localURL, writeToRequestConfig, this.path, this.patchType, this.requestAttribute, kind, String.format("%s%s",this.label,kind), this.patchContentType,kind);
		    } else  {
		    	doPut(localTemplate, approvalID, String.format("%s/%s", localURL,objectName), con, os, token, localTarget, kind);
        	}
		} else {
			doPut(localTemplate, approvalID, String.format("%s/%s", localURL,objectName), con, os, token, localTarget, kind);
		}
	}

	private void doPut(String localTemplate, int approvalID, String localURL, HttpCon con, OpenShiftTarget os,
			String token, String localTarget, String kind)
			throws IOException, ClientProtocolException, ParseException, ProvisioningException {
		String respJSON = os.callWSPut(token, con, localURL, localTemplate);
		
		if (logger.isDebugEnabled()) {
		    logger.debug("Response for putting object : '" + respJSON + "'");
		}

		JSONParser parser = new JSONParser();
		JSONObject resp = (JSONObject) parser.parse(respJSON);
		String localkind = (String) resp.get("kind");
		String projectName = (String) ((JSONObject) resp.get("metadata")).get("name");


		if (! localkind.equalsIgnoreCase(kind)) {
		    throw new ProvisioningException("Could not create " + kind + " with json '" + localTemplate + "' - '" + respJSON + "'" );
		} else {
		    this.task.getConfigManager().getProvisioningEngine().logAction(localTarget,true, ProvisioningUtil.ActionType.Replace,  approvalID, this.task.getWorkflow(), String.format("%s%s",this.label,kind), projectName);
		}
	}
	
	private void doPatch(String objectName, Map<String, Object> request, WorkflowTask task, String template,String targetName,String url,String writeToRequestConfig,String path,String patchType,String requestAttribute,String expKind,String label,String patchContentType,String kind) throws ProvisioningException {
		
		PatchK8sObject.doPatch(request, task, template, this.targetName, url, writeToRequestConfig, path, patchType, requestAttribute, kind, label, patchContentType);
	}
	
}
