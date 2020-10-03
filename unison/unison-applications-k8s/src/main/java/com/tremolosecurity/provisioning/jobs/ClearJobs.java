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
package com.tremolosecurity.provisioning.jobs;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.HashMap;

import org.apache.logging.log4j.Logger;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.quartz.JobExecutionContext;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.scheduler.UnisonJob;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;
import com.tremolosecurity.unison.openshiftv3.jobs.DeleteObject;

public class ClearJobs extends UnisonJob {
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(ClearJobs.class.getName());

	@Override
	public void execute(ConfigManager configManager, JobExecutionContext context) throws ProvisioningException {
		if (configManager == null || configManager.getProvisioningEngine() == null) {
			logger.warn("System not fully initialized");
			return;
		}
		
		
		String target = context.getJobDetail().getJobDataMap().getString("target");
		String uri = context.getJobDetail().getJobDataMap().getString("uri");
		String labels = context.getJobDetail().getJobDataMap().getString("labels");
		String workflowName = context.getJobDetail().getJobDataMap().getString("workflow");
		String runWorkflowAsUsername = context.getJobDetail().getJobDataMap().getString("runWorkflowAsUsername");
		String runWorkflowAsUsernameAttribute = context.getJobDetail().getJobDataMap().getString("runWorkflowAsUsernameAttribute");
		
		OpenShiftTarget os = (OpenShiftTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(target).getProvider();
		HttpCon con = null;
		
		try {
			con = os.createClient();
			String token = os.getAuthToken();
			String finalUri = uri + "?labelSelector=" + URLEncoder.encode(labels,"UTF-8");
			String jsonResponse = os.callWS(token, con, finalUri);
			
			logger.info(jsonResponse);
			
			JSONObject root = (JSONObject) new JSONParser().parse(jsonResponse);
			JSONArray items = (JSONArray) root.get("items");
			
			for (Object o : items) {
				JSONObject job = (JSONObject) o;
				JSONObject metadata = (JSONObject) job.get("metadata");
				JSONObject status = (JSONObject) job.get("status");
				
				if (status != null) {
					Long succeed = (Long) status.get("succeeded");
					if (succeed != null && succeed.intValue() == 1) {
						HashMap<String,Object> request = new HashMap<String,Object>();
						request.put("job_name", (String) metadata.get("name"));
						
						JSONObject jobLabels = (JSONObject) metadata.get("labels");
						if (jobLabels != null) {
							for (Object keyO : jobLabels.keySet()) {
								String key = (String) keyO;
								logger.info("label - '" + key + "'='" + jobLabels.get(key) + "'");
								request.put("job_labels_" + key,jobLabels.get(key));
							}
						}
						
						User user = new User();
						user.setUserID(runWorkflowAsUsername);
						user.setRequestReason("Clearing completed job " + metadata.get("name"));
						user.getAttribs().put(runWorkflowAsUsernameAttribute, new Attribute(runWorkflowAsUsernameAttribute,runWorkflowAsUsername));
						Workflow wf = GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getWorkFlow(workflowName, user);
						logger.info(request);
						wf.executeWorkflow(user, request);
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
