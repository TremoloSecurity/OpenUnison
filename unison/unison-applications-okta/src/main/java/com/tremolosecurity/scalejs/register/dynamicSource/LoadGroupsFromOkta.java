/*******************************************************************************
 * Copyright 2021 Tremolo Security, Inc.
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
package com.tremolosecurity.scalejs.register.dynamicSource;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;

import com.okta.sdk.resource.client.ApiClient;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.scalejs.cfg.ScaleAttribute;
import com.tremolosecurity.scalejs.sdk.SourceList;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.okta.provisioning.OktaTarget;
import com.tremolosecurity.util.NVP;

public class LoadGroupsFromOkta implements SourceList {
	
	static Logger logger = Logger.getLogger(LoadGroupsFromOkta.class);

	String targetName;
	String errorMessage;
	int maxEntries;

	private boolean dynSearch;
	
	
	@Override
	public void init(ScaleAttribute attribute, Map<String, Attribute> config) {
		if ( config.get("targetName") == null) {
			logger.error("targetName is not configured");
		} else {
			this.targetName = config.get("targetName").getValues().get(0);
		}
		errorMessage = config.get("errorMessage").getValues().get(0);
		maxEntries = Integer.parseInt(config.get("maxEntries").getValues().get(0));
		dynSearch = attribute.getType().equalsIgnoreCase("text-list");
	}

	@Override
	public List<NVP> getSourceList(HttpFilterRequest request) throws Exception {
		if (targetName == null) {
			throw new Exception("targetName not configured");
		}
		
		OktaTarget okta = (OktaTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(this.targetName).getProvider();
		
		if (okta == null) {
			throw new Exception("The target " + targetName + " does not exist");
		}
		
		ApiClient client = okta.getOkta();
		
		
		if (request.getParameter("search") == null ) {
			ArrayList<NVP> toReturn = new ArrayList<NVP>();
			List<com.okta.sdk.resource.model.Group> groupList  = okta.getGroupApi().listGroups(null, null, null, null, null, null, null, null);
			int i = 0;
			for (com.okta.sdk.resource.model.Group group : groupList) {
				toReturn.add(new NVP(group.getProfile().getName(),group.getProfile().getName()));
				if (this.dynSearch && i >= this.maxEntries) {
					break;
				}
			}
			
			Collections.sort(toReturn, new Comparator<NVP>() {

				@Override
				public int compare(NVP arg0, NVP arg1) {
					return arg0.getName().compareTo(arg1.getName());
				}});
			
			return toReturn;
		} else {
			int i = 0;
			ArrayList<NVP> toReturn = new ArrayList<NVP>();
			
			List<com.okta.sdk.resource.model.Group> groupList  = okta.getGroupApi().listGroups(request.getParameter("search").getValues().get(0),null, null, null, null, null, null, null);
			
			
			for (com.okta.sdk.resource.model.Group group : groupList) {
				toReturn.add(new NVP(group.getProfile().getName(),group.getProfile().getName()));
				i++;
				if (i >= this.maxEntries) {
					break;
				}
			}
			
			Collections.sort(toReturn, new Comparator<NVP>() {

				@Override
				public int compare(NVP arg0, NVP arg1) {
					return arg0.getName().compareTo(arg1.getName());
				}});
			
			return toReturn;
		}
		
		
	}

	@Override
	public String validate(String value, HttpFilterRequest request) throws Exception {
		if (targetName == null) {
			throw new Exception("targetName not configured");
		}
		
		OktaTarget okta = (OktaTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(this.targetName).getProvider();
		
		if (okta == null) {
			throw new Exception("The target " + targetName + " does not exist");
		}
		
		
		logger.info("validating okta group '" + value + "'");
		List<com.okta.sdk.resource.model.Group>  groupList = okta.getGroupApi().listGroups(value, null, null, null, null, null, null, null);
		
		if (groupList.size() == 0) {
			return this.errorMessage;
		}
		
		com.okta.sdk.resource.model.Group group = groupList.get(0);
		
		if (group == null || ! group.getProfile().getName().equals(value)) {
			return this.errorMessage;
		} else {
			return null;
		}
		
	}

}
