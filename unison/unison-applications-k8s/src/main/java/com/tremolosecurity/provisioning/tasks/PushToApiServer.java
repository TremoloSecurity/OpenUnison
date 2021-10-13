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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.yaml.snakeyaml.Yaml;


import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.tasks.dataobj.GitFile;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;


public class PushToApiServer implements CustomTask {
	
	static Logger logger = Logger.getLogger(PushToApiServer.class);

	
	
	String target;
	String requestObject;
	
	
	transient WorkflowTask task;
	
	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
		this.task = task;
		
		this.target = params.get("target").getValues().get(0);
		this.requestObject = params.get("requestObject").getValues().get(0);
		
		

	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
		this.task = task;

	}

	@Override
	public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {
		String localTarget = task.renderTemplate(this.target, request);
		
		OpenShiftTarget target = (OpenShiftTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(localTarget).getProvider();
		
		HttpCon con = null;
		
		
		
		try {
			con = target.createClient();
			StringBuilder sb = new StringBuilder();
			
			
			List<GitFile> files = (List<GitFile>) request.get(requestObject);
			
			if (files == null) {
				throw new Exception("No gitfiles stored in '" + requestObject + "'");
			}
			
			
			
			for (GitFile f : files) {
				
				Yaml yaml = new Yaml();
    			Map<String,Object> map= (Map<String, Object>) yaml.load(new ByteArrayInputStream(f.getData().getBytes("UTF-8")));
    			JSONObject jsonObject=new JSONObject(map);
    			String localTemplateJSON = jsonObject.toJSONString();
    			
    			if (! target.isObjectExistsByName(target.getAuthToken(), con, f.getDirName(), f.getFileName())) {
    				logger.info(new StringBuilder().append("Writing ").append(f.getDirName()).append('/').append(f.getFileName()).toString());
    				target.callWSPost(target.getAuthToken(), con, f.getDirName(), localTemplateJSON);
    			}
    			
    			
    			
			}
			
			
			
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not push to git",e);
		} finally {
			if (con != null) {
				try {
					con.getHttp().close();
				} catch (IOException e) {
					
				}
				con.getBcm().close();
			}
			

		}
		
		
		return true;
	}

}
