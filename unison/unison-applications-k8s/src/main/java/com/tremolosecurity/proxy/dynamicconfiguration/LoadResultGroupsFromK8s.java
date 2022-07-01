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
package com.tremolosecurity.proxy.dynamicconfiguration;

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

public class LoadResultGroupsFromK8s  implements DynamicResultGroups, K8sWatchTarget {
static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(LoadResultGroupsFromK8s.class.getName());
	
	K8sWatcher k8sWatch;
	
	TremoloType tremolo;

	private ProvisioningEngine provisioningEngine;
	private ConfigManager cfgMgr;
	
	private ResultGroupType createResultGroup(JSONObject item, String name) throws ProvisioningException {
		
		ResultGroupType rgt = new ResultGroupType();
		
		JSONArray spec = (JSONArray) item.get("spec");
		
		for (Object o : spec) {
			JSONObject jsonObj = (JSONObject) o;
			ResultType rt = new ResultType();
			rt.setType((String) jsonObj.get("resultType"));
			rt.setSource((String) jsonObj.get("source"));
			rt.setValue((String) jsonObj.get("value"));
			rgt.getResult().add(rt);
		}
		
		rgt.setName(name);
		
		return rgt;
		
		
	}

	
	
	@Override
	public void loadDynamicResultGroups(ConfigManager cfgMgr, ProvisioningEngine provisioningEngine,
			Map<String, Attribute> init) throws ProvisioningException {
		this.tremolo = cfgMgr.getCfg();
		String k8sTarget = 	init.get("k8starget").getValues().get(0);
		String namespace = init.get("namespace").getValues().get(0);
		
		
		
		this.provisioningEngine = provisioningEngine;
		this.cfgMgr = cfgMgr;
		
		this.k8sWatch = new K8sWatcher(k8sTarget,namespace,"resultgroups","openunison.tremolo.io",this,cfgMgr,provisioningEngine);
		
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
			
			logger.info("Adding result group " + name);
			
			ResultGroupType rgt = this.createResultGroup(newRoot, name);
			
			ResultGroupType rgtToRemove = null;
			for (ResultGroupType rgtCheck : cfg.getResultGroups().getResultGroup()) {
				if (rgtCheck.getName().equalsIgnoreCase(name)) {
					rgtToRemove = rgtCheck;
					break;
				}
			}
			
			if (rgtToRemove != null) {
				cfg.getResultGroups().getResultGroup().remove(rgtToRemove);
			}
			
			cfg.getResultGroups().getResultGroup().add(rgt);
			
			GlobalEntries.getGlobalEntries().getConfigManager().addResultGroup(rgt);
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
			
			logger.info("modifying result group " + name);
			
			ResultGroupType rgt = this.createResultGroup(newRoot, name);
			
			ResultGroupType rgtToRemove = null;
			for (ResultGroupType rgtCheck : cfg.getResultGroups().getResultGroup()) {
				if (rgtCheck.getName().equalsIgnoreCase(name)) {
					rgtToRemove = rgtCheck;
					break;
				}
			}
			
			if (rgtToRemove != null) {
				cfg.getResultGroups().getResultGroup().remove(rgtToRemove);
			}
			
			cfg.getResultGroups().getResultGroup().add(rgt);
			
			GlobalEntries.getGlobalEntries().getConfigManager().addResultGroup(rgt);
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
		
		logger.info("Deleting result group " + name);
		
		ResultGroupType rgtToRemove = null;
		for (ResultGroupType rgtCheck : cfg.getResultGroups().getResultGroup()) {
			if (rgtCheck.getName().equalsIgnoreCase(name)) {
				rgtToRemove = rgtCheck;
				break;
			}
		}
		
		if (rgtToRemove != null) {
			cfg.getResultGroups().getResultGroup().remove(rgtToRemove);
			GlobalEntries.getGlobalEntries().getConfigManager().removeResultGroup(rgtToRemove);
		}
		
		
		
		
		
	}
	
	
}
