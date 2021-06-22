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
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.AuthLockoutType;
import com.tremolosecurity.config.xml.AuthMechParamType;
import com.tremolosecurity.config.xml.AuthMechType;
import com.tremolosecurity.config.xml.ConfigType;
import com.tremolosecurity.config.xml.CustomAzRuleType;
import com.tremolosecurity.config.xml.MechanismType;
import com.tremolosecurity.config.xml.ParamListType;
import com.tremolosecurity.config.xml.ParamType;
import com.tremolosecurity.config.xml.ResultGroupType;
import com.tremolosecurity.config.xml.ResultType;
import com.tremolosecurity.config.xml.TargetType;
import com.tremolosecurity.config.xml.TremoloType;
import com.tremolosecurity.k8s.watch.K8sWatchTarget;
import com.tremolosecurity.k8s.watch.K8sWatcher;
import com.tremolosecurity.openunison.util.config.OpenUnisonConfigLoader;
import com.tremolosecurity.provisioning.core.ProvisioningEngine;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.proxy.dynamicloaders.DynamicAuthChains;
import com.tremolosecurity.proxy.dynamicloaders.DynamicAuthMechs;
import com.tremolosecurity.proxy.dynamicloaders.DynamicAuthorizations;
import com.tremolosecurity.proxy.dynamicloaders.DynamicResultGroups;
import com.tremolosecurity.provisioning.targets.LoadTargetsFromK8s;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;

public class LoadAuthChainsFromK8s  implements DynamicAuthChains, K8sWatchTarget {
static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(LoadAuthChainsFromK8s.class.getName());
	
	K8sWatcher k8sWatch;
	
	TremoloType tremolo;

	private ProvisioningEngine provisioningEngine;
	private ConfigManager cfgMgr;
	
	
	private AuthChainType createAuthChain (JSONObject item, String name) throws Exception {
		AuthChainType act = new AuthChainType();
		
		act.setName(name);
		
		JSONObject spec = (JSONObject) item.get("spec");
		
		act.setLevel(((Long)spec.get("level")).intValue());
		
		Boolean finishOnRequiredSucess = (Boolean) spec.get("finishOnRequiredSucess");
		
		if (finishOnRequiredSucess != null) {
			act.setFinishOnRequiredSucess(finishOnRequiredSucess);
		} else {
			act.setFinishOnRequiredSucess(false);
		}
		
		String root = (String) spec.get("root");
		if (root != null) {
			act.setRoot(root);
		}
		
		JSONObject jsonCompliance = (JSONObject) spec.get("compliance");
		if (jsonCompliance != null) {
			AuthLockoutType alt = new AuthLockoutType();
			alt.setEnabled((Boolean) jsonCompliance.get("enabled"));
			alt.setMaxFailedAttempts(((Integer)jsonCompliance.get("maxLockoutTime")));
			alt.setNumFailedAttribute((String) jsonCompliance.get("numFailedAttribute"));
			alt.setLastFailedAttribute((String) jsonCompliance.get("lastFailedAttribute"));
			alt.setLastSucceedAttribute((String) jsonCompliance.get("lastSucceedAttribute"));
			alt.setUpdateAttributesWorkflow((String) jsonCompliance.get("updateAttributesWorkflow"));
			alt.setUidAttributeName((String) jsonCompliance.get("uidAttributeName"));
			
			act.setCompliance(alt);
		}
		
		JSONArray mechs = (JSONArray) spec.get("authMechs");
		for (Object o : mechs) {
			JSONObject mech = (JSONObject) o;
			AuthMechType amt = new AuthMechType();
			amt.setName((String) mech.get("name"));
			amt.setRequired((String) mech.get("required"));
			amt.setParams(new AuthMechParamType());
			JSONObject jsonObj = (JSONObject) mech.get("params");
			for (Object ok : jsonObj.keySet()) {
				String paramName = (String) ok;
				Object val = jsonObj.get(paramName);
				
				if (val instanceof String) {
					ParamType pt = new ParamType();
					pt.setName(paramName);
					pt.setValue((String) val);
					amt.getParams().getParam().add(pt);
				} else {
					JSONArray vals = (JSONArray) val;
					for (Object ov : vals) {
						ParamType pt = new ParamType();
						pt.setName(paramName);
						pt.setValue((String) ov);
						amt.getParams().getParam().add(pt);
					}
				}
			}
			
			JSONArray secretParams = (JSONArray) mech.get("secretParams");
			
			if (secretParams != null) {
				HttpCon nonwatchHttp = this.k8sWatch.getK8s().createClient();
				String token = this.k8sWatch.getK8s().getAuthToken();
				
				try {
					for (Object ox : secretParams) {
						JSONObject secretParam = (JSONObject) ox;
						String paramName = (String) secretParam.get("name");
						String secretName = (String) secretParam.get("secretName");
						String secretKey = (String) secretParam.get("secretKey");
						
						String secretValue = this.k8sWatch.getSecretValue(secretName, secretKey, token, nonwatchHttp);
						ParamType pt = new ParamType();
						pt.setName(paramName);
						pt.setValue(secretValue);
						
						amt.getParams().getParam().add(pt);
						
					}
				} finally {
					nonwatchHttp.getHttp().close();
					nonwatchHttp.getBcm().close();
				}
			}
			
			act.getAuthMech().add(amt);
		}
		
		return act;
		
	}
	
	
	

	
	
	@Override
	public void loadDynamicAuthChains(ConfigManager cfgMgr, ProvisioningEngine provisioningEngine,
			Map<String, Attribute> init) throws ProvisioningException {
		this.tremolo = cfgMgr.getCfg();
		String k8sTarget = 	init.get("k8starget").getValues().get(0);
		String namespace = init.get("namespace").getValues().get(0);
		String uri = "/apis/openunison.tremolo.io/v1/namespaces/" + namespace + "/authchains";
		
		
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
			
			logger.info("Adding authentication chain " + name);
			
			
			try {
				AuthChainType act = this.createAuthChain(item, name);
				
				
				
				
				synchronized(GlobalEntries.getGlobalEntries().getConfigManager().getAuthChains()) {
					GlobalEntries.getGlobalEntries().getConfigManager().getAuthChains().put(name, act);
				}
				
				synchronized (GlobalEntries.getGlobalEntries().getConfigManager().getCfg()) {
					AuthChainType curAct = null;
					for (AuthChainType itAct : GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getAuthChains().getChain()) {
						if (itAct.getName().equals(act.getName())) {
							curAct = itAct;
							break;
						}
					}
					
					if (curAct != null) {
						GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getAuthChains().getChain().remove(curAct);
					}
					
					GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getAuthChains().getChain().add(act);
				}
			} catch (Exception e) {
				logger.warn("Could not initialize authentication chain " + name,e);
			}
			
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
			
			logger.info("Modifying authentication chain " + name);
			
			try {
				AuthChainType act = this.createAuthChain(item, name);
				synchronized(GlobalEntries.getGlobalEntries().getConfigManager().getAuthChains()) {
					GlobalEntries.getGlobalEntries().getConfigManager().getAuthChains().put(name, act);
				}
				
				synchronized (GlobalEntries.getGlobalEntries().getConfigManager().getCfg()) {
					AuthChainType curAct = null;
					for (AuthChainType itAct : GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getAuthChains().getChain()) {
						if (itAct.getName().equals(act.getName())) {
							curAct = itAct;
							break;
						}
					}
					
					if (curAct != null) {
						GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getAuthChains().getChain().remove(curAct);
					}
					
					GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getAuthChains().getChain().add(act);
				}
			} catch (Exception e) {
				logger.warn("Could not initialize authentication chain " + name,e);
			}
			
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
		
		logger.info("Deleting authentication mechanism" + name);
		
		synchronized(GlobalEntries.getGlobalEntries().getConfigManager().getAuthChains()) {
			GlobalEntries.getGlobalEntries().getConfigManager().getAuthChains().remove(name);
		}
		
		
	}
	
	
}
