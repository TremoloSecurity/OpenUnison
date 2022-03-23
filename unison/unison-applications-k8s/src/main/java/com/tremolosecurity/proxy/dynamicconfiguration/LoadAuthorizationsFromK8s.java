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
import com.tremolosecurity.config.xml.CustomAzRuleType;
import com.tremolosecurity.config.xml.ParamType;
import com.tremolosecurity.config.xml.ParamWithValueType;
import com.tremolosecurity.config.xml.ResultGroupType;
import com.tremolosecurity.config.xml.ResultType;
import com.tremolosecurity.config.xml.TargetType;
import com.tremolosecurity.config.xml.TremoloType;
import com.tremolosecurity.k8s.watch.K8sWatchTarget;
import com.tremolosecurity.k8s.watch.K8sWatcher;
import com.tremolosecurity.openunison.util.config.OpenUnisonConfigLoader;
import com.tremolosecurity.provisioning.core.ProvisioningEngine;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.proxy.dynamicloaders.DynamicAuthorizations;
import com.tremolosecurity.proxy.dynamicloaders.DynamicResultGroups;
import com.tremolosecurity.provisioning.targets.LoadTargetsFromK8s;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;

public class LoadAuthorizationsFromK8s  implements DynamicAuthorizations, K8sWatchTarget {
static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(LoadAuthorizationsFromK8s.class.getName());
	
	K8sWatcher k8sWatch;
	
	TremoloType tremolo;

	private ProvisioningEngine provisioningEngine;
	private ConfigManager cfgMgr;
	
	private CustomAzRuleType createCustomAz(JSONObject item, String name) throws ProvisioningException {
		
		CustomAzRuleType cart = new CustomAzRuleType();
		
		JSONObject spec = (JSONObject) item.get("spec");
		
		cart.setName(name);
		cart.setClassName((String) spec.get("className"));
		JSONObject params = (JSONObject) spec.get("params");
		
		for (Object o : params.keySet()) {
			String keyName = (String) o;
			Object v = params.get(keyName);
			if (v instanceof String) {
				String val = (String) v;
				ParamWithValueType pt = new ParamWithValueType();
				pt.setName(keyName);
				pt.setValue(val);
				cart.getParams().add(pt);
			} else if (v instanceof JSONArray) {
				for (Object ov : ((JSONArray) v)) {
					ParamWithValueType pt = new ParamWithValueType();
					pt.setName(keyName);
					pt.setValue((String) ov);
					cart.getParams().add(pt);
				}
			}
		}
		
		JSONArray secretParams = (JSONArray) spec.get("secretParams");
		
		if (secretParams != null) {
			try {
				HttpCon nonwatchHttp = this.k8sWatch.getK8s().createClient();
				String token = this.k8sWatch.getK8s().getAuthToken();
				
				try {
					for (Object ox : secretParams) {
						JSONObject secretParam = (JSONObject) ox;
						String paramName = (String) secretParam.get("name");
						String secretName = (String) secretParam.get("secretName");
						String secretKey = (String) secretParam.get("secretKey");
						
						String secretValue = this.k8sWatch.getSecretValue(secretName, secretKey, token, nonwatchHttp);
						ParamWithValueType pt = new ParamWithValueType();
						pt.setName(paramName);
						pt.setValue(secretValue);
						
						cart.getParams().add(pt);
						
					}
				} finally {
					nonwatchHttp.getHttp().close();
					nonwatchHttp.getBcm().close();
				}
			} catch (Exception e) {
				throw new ProvisioningException("Could not generate secret params from '" + name + "'",e);
			}
		}
		
		return cart;
		
	}

	
	
	@Override
	public void loadDynamicAuthorizations(ConfigManager cfgMgr, ProvisioningEngine provisioningEngine,
			Map<String, Attribute> init) throws ProvisioningException {
		this.tremolo = cfgMgr.getCfg();
		String k8sTarget = 	init.get("k8starget").getValues().get(0);
		String namespace = init.get("namespace").getValues().get(0);
		String uri = "/apis/openunison.tremolo.io/v1/namespaces/" + namespace + "/customazs";
		
		
		this.provisioningEngine = provisioningEngine;
		this.cfgMgr = cfgMgr;
		
		this.k8sWatch = new K8sWatcher(k8sTarget,namespace,uri,this,cfgMgr,provisioningEngine);
		
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
			
			logger.info("Adding custom authorization " + name);
			
			CustomAzRuleType newAzRuleType = this.createCustomAz(item, name);
			
			
			
			GlobalEntries.getGlobalEntries().getConfigManager().addCustomerAuthorization(newAzRuleType);
		} catch (ParseException e) {
			throw new ProvisioningException("Could not parse custom authorization",e);
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
			
			logger.info("Modifying custom authorization " + name);
			
			CustomAzRuleType newAzRuleType = this.createCustomAz(item, name);
			
			
			
			GlobalEntries.getGlobalEntries().getConfigManager().addCustomerAuthorization(newAzRuleType);
		} catch (ParseException e) {
			throw new ProvisioningException("Could not parse custom authorization",e);
		}
		
	}



	@Override
	public void deleteObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
		JSONObject metadata = (JSONObject) item.get("metadata");
		
		if (metadata == null) {
			throw new ProvisioningException("No metadata");
		}
		
		String name = (String) metadata.get("name");
		
		logger.info("Deleting custom authorization " + name);
		
		GlobalEntries.getGlobalEntries().getConfigManager().removeCustomAuthorization(name);
		
		
	}
	
	
}
