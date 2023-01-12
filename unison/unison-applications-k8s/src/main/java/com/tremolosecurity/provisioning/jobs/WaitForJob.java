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

package com.tremolosecurity.provisioning.jobs;

import java.io.IOException;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

import org.apache.log4j.Logger;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.quartz.JobExecutionContext;

import com.cedarsoftware.util.io.JsonReader;
import com.google.gson.Gson;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.json.Token;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.ProvisioningTarget;
import com.tremolosecurity.provisioning.core.ProvisioningUtil;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.scheduler.UnisonJob;
import com.tremolosecurity.provisioning.tasks.dataobj.WaitForState;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;

public class WaitForJob extends UnisonJob {
	
	static Logger logger = Logger.getLogger(WaitForJob.class.getName());

	@Override
	public void execute(ConfigManager configManager, JobExecutionContext context) throws ProvisioningException {
		if (configManager == null || configManager.getProvisioningEngine() == null) {
			logger.warn("System not fully initialized");
			return;
		}
		
		Gson gson = new Gson();
		
		String target = context.getJobDetail().getJobDataMap().getString("target");
		String namespace = context.getJobDetail().getJobDataMap().getString("namespace");
		
		OpenShiftTarget os = (OpenShiftTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(target).getProvider();
		HttpCon con = null;
		
		try {
			con = os.createClient();
			String token = os.getAuthToken();
			
			String jsonResp = os.callWS(token, con, "/apis/openunison.tremolo.io/v1/namespaces/" + namespace + "/waitforstates");
			
			JSONObject root = (JSONObject) new JSONParser().parse(jsonResp);
			if (root.get("items") == null) {
				//no list returned
				logger.warn("Couldn't load waitforstates: " + jsonResp);
				return;
			} else {
				JSONArray items = (JSONArray) root.get("items");
				for (Object o : items) {
					JSONObject waitfor = (JSONObject) o;
					
					String waitForName = (String) ((JSONObject)waitfor.get("metadata")).get("name");
					
					
					Token encWaitfor = gson.fromJson( new String(Base64.getDecoder().decode( (String)((JSONObject) waitfor.get("spec") ).get("state") )), Token.class);
					
					byte[] iv = org.bouncycastle.util.encoders.Base64.decode(encWaitfor.getIv());
					
					
				    IvParameterSpec spec =  new IvParameterSpec(iv);
				    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
					cipher.init(Cipher.DECRYPT_MODE, configManager.getSecretKey(configManager.getCfg().getProvisioning().getApprovalDB().getEncryptionKey()),spec);
				    
					byte[] encBytes = org.bouncycastle.util.encoders.Base64.decode(encWaitfor.getEncryptedRequest());
					
					
					String jsonDecr = new String(cipher.doFinal(encBytes));
					
					
					WaitForState wfs = (WaitForState) JsonReader.jsonToJava(jsonDecr);
					
					ProvisioningTarget checkTarget = configManager.getProvisioningEngine().getTarget(wfs.getTarget());
					if (checkTarget == null) {
						logger.warn(String.format("Could not load target %s from %s", wfs.getTarget(),waitForName));
						continue;
					}
					
					if (! (checkTarget.getProvider() instanceof OpenShiftTarget)) {
						logger.warn(String.format("target %s from %s is not of type OpenShiftTarget", wfs.getTarget(),waitForName));
						continue;
					}
					
					OpenShiftTarget checkK8s = (OpenShiftTarget) checkTarget.getProvider();
					
					HttpCon checkCon = null;
					
					try {
						checkCon = checkK8s.createClient();
						String checkToken = checkK8s.getAuthToken();
						
						String checkJson = checkK8s.callWS(checkToken, con, wfs.getUri());
						
						JSONObject respObj = (JSONObject) new JSONParser().parse(checkJson);
						if (respObj.get("kind").equals("Status")) {
							logger.warn(String.format("Could not load %s - %s, %s", waitForName, wfs.getUri(),checkJson));
							continue;
						} else {
							logger.info(String.format("For %s, found %s", waitForName, wfs.getUri()));
							
							int numFound = 0;
							
							for (String jsonPath : wfs.getConditions().keySet()) {
								String condition = wfs.getConditions().get(jsonPath);
								if (jsonPath.startsWith(".")) {
									jsonPath = String.format("$%s", jsonPath);
								}
								
								Object resp = null;

								try {
									resp = JsonPath.read(checkJson, jsonPath);
								} catch (PathNotFoundException e) {
									resp = null;
								}
								
								if (resp == null) {
									logger.warn(String.format("Could not find path %s for %s",jsonPath,waitForName));
									continue;
								}
								
								if (! resp.toString().equals(condition)) {
									logger.warn(String.format("Path %s for %s does not equal - actual/exp %s/%s",jsonPath,waitForName,resp.toString(),condition));
									continue;
								} else {
									numFound++;
									if (logger.isDebugEnabled()) {
										logger.debug(String.format("Path %s for %s equal - %s",jsonPath,waitForName,resp.toString()));
										continue;
									}
								}
							}
							
							if (numFound != wfs.getConditions().keySet().size()) {
								logger.warn(String.format("Not all conditions met for %s", waitForName));
								continue;
							} else {
								if (logger.isDebugEnabled()) {
									logger.debug(String.format("All conditions met for %s",waitForName));
								}
								
								Workflow wf = (Workflow) JsonReader.jsonToJava(new String(Base64.getDecoder().decode(wfs.getBase64Workflow())));
								
								
								
								
								
								int approvalID = 0;
								
						        if (wf.getRequest().containsKey("APPROVAL_ID")) {
						            approvalID = (Integer) wf.getRequest().get("APPROVAL_ID");
						        }


						        String resp = os.callWSDelete(token, con, String.format("/apis/openunison.tremolo.io/v1/namespaces/%s/waitforstates/%s", namespace, waitForName));
						        
						        configManager.getProvisioningEngine().logAction(target,true, ProvisioningUtil.ActionType.Delete,  approvalID, wf, "kubernetes-waitforstate", waitForName);
						        
						        wf.reInit(configManager);
								wf.restart();
							}
						}
					} finally {
						if (checkCon != null) {
							try {
								checkCon.getHttp().close();
							} catch (IOException e) {
								//do nothing
							}
							
							checkCon.getBcm().close();
						}
					}
					
				}
			}
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not clear object",e);
		} finally {
			if (con != null) {
				con.getBcm().close();
				try {
					con.getHttp().close();
				} catch (IOException e) {
					logger.warn("Could not close connection",e);
				}
			}
		}
	}

}
