/*******************************************************************************
 * Copyright 2024 Tremolo Security, Inc.
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
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;

import com.tremolosecurity.provisioning.core.providers.AzureADProvider;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.scalejs.cfg.ScaleAttribute;
import com.tremolosecurity.scalejs.sdk.SourceList;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.util.NVP;

public class EntraIDSource implements SourceList {
	
	static Logger logger = Logger.getLogger(EntraIDSource.class);
	String target;
	int maxEntries;
	
	@Override
	public void init(ScaleAttribute attribute, Map<String, Attribute> config) {
		this.target = config.get("target").getValues().get(0);
		this.maxEntries = Integer.parseInt(config.get("maxEntries").getValues().get(0));
		
	}

	@Override
	public List<NVP> getSourceList(HttpFilterRequest request) throws Exception {
		AzureADProvider entraid = (AzureADProvider) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(this.target).getProvider();
		
		List<String> groups;
		
		Attribute search = request.getParameter("search");
		if (search != null) {
			groups = entraid.searchGroups(search.getValues().get(0), maxEntries);
		} else {
			groups = entraid.searchGroups("", maxEntries);
		}
		
		List<NVP> groupsList = new ArrayList<NVP>();
		for (String group : groups) {
			groupsList.add(new NVP(group,group));
		}
		
		return groupsList;
		
	}

	@Override
	public String validate(String value, HttpFilterRequest request) throws Exception {
		
		AzureADProvider entraid = (AzureADProvider) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(this.target).getProvider();
		if (entraid.isGroupExists(value, null, null)) {
			return null;
		} else {
			return String.format("Group %s not found", value);
		}
		
	}

}
