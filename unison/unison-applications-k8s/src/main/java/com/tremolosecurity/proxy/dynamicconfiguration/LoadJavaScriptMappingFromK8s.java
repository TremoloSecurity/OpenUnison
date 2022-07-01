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
package com.tremolosecurity.proxy.dynamicconfiguration;

import java.util.HashMap;
import java.util.Map;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.ResultGroupType;
import com.tremolosecurity.config.xml.ResultType;
import com.tremolosecurity.config.xml.TargetType;
import com.tremolosecurity.config.xml.TremoloType;
import com.tremolosecurity.k8s.watch.K8sWatchTarget;
import com.tremolosecurity.k8s.watch.K8sWatcher;
import com.tremolosecurity.openunison.util.config.OpenUnisonConfigLoader;
import com.tremolosecurity.provisioning.core.ProvisioningEngine;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.proxy.dynamicloaders.DynamicResultGroups;
import com.tremolosecurity.provisioning.targets.LoadTargetsFromK8s;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;

public class LoadJavaScriptMappingFromK8s  implements K8sWatchTarget {
static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(LoadJavaScriptMappingFromK8s.class.getName());
	
	K8sWatcher k8sWatch;
	
	TremoloType tremolo;

	Map<String,String> maps;
	
	private ConfigManager cfgMgr;
	
	
	public LoadJavaScriptMappingFromK8s() {
		this.maps = new HashMap<String,String>();
	}
	
	public String getMapping(String name) {
		return this.maps.get(name);
	}
	
	
	public void loadJavaScriptMappings(ConfigManager cfgMgr, 
			String k8sTarget,String namespace) throws ProvisioningException {
		this.tremolo = cfgMgr.getCfg();
		
		
		
		
		
		this.cfgMgr = cfgMgr;
		
		this.k8sWatch = new K8sWatcher(k8sTarget,namespace,"javascriptmappings","openunison.tremolo.io",this,cfgMgr,cfgMgr.getProvisioningEngine());
		
		this.k8sWatch.initalRun();

	}



	@Override
	public void addObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
		String rawJson = item.toJSONString();
		StringBuffer b = new StringBuffer();
		b.setLength(0);
		OpenUnisonConfigLoader.integrateIncludes(b,rawJson);
		try {
			JSONObject newRoot = (JSONObject) new JSONParser().parse(b.toString());
			JSONObject metadata = (JSONObject) newRoot.get("metadata");
			
			if (metadata == null) {
				throw new ProvisioningException("No metadata");
			}
			
			String name = (String) metadata.get("name");
			
			logger.info("Adding mapping " + name);
			
			maps.put(name, (String) ((JSONObject)newRoot.get("spec")).get("javascript"));
		} catch (ParseException e) {
			throw new ProvisioningException("Could not parse resultgroup",e);
		}
		
	}



	@Override
	public void modifyObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
		String rawJson = item.toJSONString();
		StringBuffer b = new StringBuffer();
		b.setLength(0);
		OpenUnisonConfigLoader.integrateIncludes(b,rawJson);
		try {
			JSONObject newRoot = (JSONObject) new JSONParser().parse(b.toString());
			JSONObject metadata = (JSONObject) newRoot.get("metadata");
			
			if (metadata == null) {
				throw new ProvisioningException("No metadata");
			}
			
			String name = (String) metadata.get("name");
			
			logger.info("modifying mapping " + name);
			
			maps.put(name, (String) ((JSONObject)newRoot.get("spec")).get("javascript"));
			
		} catch (ParseException e) {
			throw new ProvisioningException("Could not parse resultgroup",e);
		}
		
	}



	@Override
	public void deleteObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
		JSONObject metadata = (JSONObject) item.get("metadata");
		
		if (metadata == null) {
			throw new ProvisioningException("No metadata");
		}
		
		String name = (String) metadata.get("name");
		
		logger.info("Deleting mapping " + name);
		
		maps.remove(name);
		
		
		
		
		
	}
	
	
}
