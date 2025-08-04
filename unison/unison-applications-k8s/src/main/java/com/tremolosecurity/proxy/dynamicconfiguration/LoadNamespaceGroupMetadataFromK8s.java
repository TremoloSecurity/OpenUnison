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

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.TremoloType;
import com.tremolosecurity.k8s.watch.K8sWatchTarget;
import com.tremolosecurity.k8s.watch.K8sWatcher;
import com.tremolosecurity.openunison.util.config.OpenUnisonConfigLoader;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.proxy.filters.SetupGroupMetadataWatch;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class LoadNamespaceGroupMetadataFromK8s implements  K8sWatchTarget {
	static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(LoadNamespaceGroupMetadataFromK8s.class.getName());
	
	K8sWatcher k8sWatch;
	
	TremoloType tremolo;

	
	private ConfigManager cfgMgr;
	
	private SetupGroupMetadataWatch md;
	
	
	
	

	
	
	
	public void loadNamespaceGroupMetadatas(ConfigManager cfgMgr, String k8sTarget, String namespace,SetupGroupMetadataWatch md) throws ProvisioningException {
		this.tremolo = cfgMgr.getCfg();
		
		
		this.md = md;
		
		this.cfgMgr = cfgMgr;
		
		this.k8sWatch = new K8sWatcher(k8sTarget,namespace,"namespacegroupmetadatas","openunison.tremolo.io",this,cfgMgr,cfgMgr.getProvisioningEngine());
		
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
			
			logger.info("Adding NamespaceGroupMetadata " + name);
			
			
			try {
				JSONObject spec = (JSONObject) newRoot.get("spec");

				this.md.addNamespaceMapping(name, spec);



				
			} catch (Exception e) {
				logger.warn("Could not initialize namespace group mapping " + name,e);
				return;
			}
			
			
			
			
		} catch (ParseException e) {
			throw new ProvisioningException("Could not parse custom namespacegroupmetadata",e);
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
			
			logger.info("Modifying NamespaceGroupMetadata " + name);
			
			
			try {
				JSONObject spec = (JSONObject) newRoot.get("spec");

				String ext = (String) spec.get("externalName");
				




				this.md.deleteNamespaceMapping(name);
				this.md.addNamespaceMapping(name,spec);
				
			} catch (Exception e) {
				logger.warn("Could not initialize namespace group mapping " + name,e);
				return;
			}
			
			
			
			
		} catch (ParseException e) {
			throw new ProvisioningException("Could not parse namespacegroupmetadata",e);
		}
		
	}



	@Override
	public void deleteObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
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
			
			logger.info("Deleting NamespaceGroupMetadata " + name);
			
			
			try {
				JSONObject spec = (JSONObject) newRoot.get("spec");
				String k8s = (String) spec.get("groupName");
				String ext = (String) spec.get("externalName");
				
				
				
				this.md.deleteNamespaceMapping(name);
				
			} catch (Exception e) {
				logger.warn("Could not delete namespace group mapping " + name,e);
				return;
			}
			
			
			
			
		} catch (ParseException e) {
			throw new ProvisioningException("Could not parse groupmetadata",e);
		}
		
		
	}
	
	
}
