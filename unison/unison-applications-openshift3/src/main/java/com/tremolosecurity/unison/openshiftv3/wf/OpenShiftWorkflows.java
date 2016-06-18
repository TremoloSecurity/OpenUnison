/*******************************************************************************
 * Copyright 2016 Tremolo Security, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package com.tremolosecurity.unison.openshiftv3.wf;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.WorkflowType;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.util.DynamicWorkflow;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;
import com.tremolosecurity.unison.openshiftv3.model.Item;
import com.tremolosecurity.unison.openshiftv3.model.groups.GroupItem;

public class OpenShiftWorkflows implements DynamicWorkflow {

	@Override
	public List<Map<String, String>> generateWorkflows(WorkflowType wf, ConfigManager cfg,
			HashMap<String, Attribute> params) throws ProvisioningException {
		ArrayList<Map<String,String>> wfData = new ArrayList<Map<String,String>>();
		
		String targetName = params.get("target").getValues().get(0);
		OpenShiftTarget target = (OpenShiftTarget) cfg.getProvisioningEngine().getTarget(targetName).getProvider();
		
		String kind = params.get("kind").getValues().get(0);
		
		try {
			String token = target.getAuthToken();
			
			
			HttpCon con = target.createClient();
			
			try {
				
				String json = target.callWS(token, con, kind);
				
				Gson gson = new Gson();
				TypeToken<com.tremolosecurity.unison.openshiftv3.model.List<Item>> tokenType = new TypeToken<com.tremolosecurity.unison.openshiftv3.model.List<Item>>() {};
				com.tremolosecurity.unison.openshiftv3.model.List<Item> list = gson.fromJson(json, tokenType.getType());
				
				for (Item item : list.getItems()) {
					HashMap<String,String> wfParams = new HashMap<String,String>();
					wfParams.put("name", (String) item.getMetadata().get("name"));
					if (item.getMetadata().containsKey("annotations")) {
						com.google.gson.internal.LinkedTreeMap annotations = (com.google.gson.internal.LinkedTreeMap) item.getMetadata().get("annotations");
						for (Object key : annotations.keySet()) {
							String keyName = (String)key;
							keyName = keyName.replace("-", "_");
							keyName = keyName.replace(".", "_");
							wfParams.put((String)keyName, (String)annotations.get(key));
						}
					}
					
					wfData.add(wfParams);
				}
				
			} finally {
				con.getBcm().close();
				con.getHttp().close();
			}
		} catch (Exception e) {
			throw new ProvisioningException("Could not load",e);
		}
		return wfData;
	}

}
