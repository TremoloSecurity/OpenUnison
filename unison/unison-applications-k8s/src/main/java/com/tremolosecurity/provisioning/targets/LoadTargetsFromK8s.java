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
package com.tremolosecurity.provisioning.targets;

import java.util.HashMap;
import java.util.Map;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.OrgType;
import com.tremolosecurity.config.xml.ParamType;
import com.tremolosecurity.config.xml.TargetAttributeType;
import com.tremolosecurity.config.xml.TargetConfigType;
import com.tremolosecurity.config.xml.TargetType;
import com.tremolosecurity.config.xml.TremoloType;
import com.tremolosecurity.k8s.watch.K8sWatchTarget;
import com.tremolosecurity.k8s.watch.K8sWatcher;
import com.tremolosecurity.openunison.util.config.OpenUnisonConfigLoader;
import com.tremolosecurity.provisioning.core.ProvisioningEngine;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.targets.DynamicTargets;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;

public class LoadTargetsFromK8s implements DynamicTargets, K8sWatchTarget {
	
	static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(LoadTargetsFromK8s.class.getName());
	
	K8sWatcher k8sWatch;
	
	TremoloType tremolo;

	private ProvisioningEngine provisioningEngine;
	private ConfigManager cfgMgr;

	@Override
	public void addObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
		
		JSONObject metadata = (JSONObject) item.get("metadata");
		String name = (String) metadata.get("name");
		logger.info("Creating target '" + name + "'");
		TargetType target = createTarget(item, name);
		this.provisioningEngine.addDynamicTarget(cfgMgr, target);
		
		
	}

	private TargetType createTarget(JSONObject item, String name) throws ProvisioningException {
		TargetType target = new TargetType();
		target.setName(name);
		target.setParams(new TargetConfigType());
		HttpCon nonwatchHttp = null;
		
		JSONObject spec = (JSONObject) item.get("spec");
		try {
			
			nonwatchHttp = this.k8sWatch.getK8s().createClient();
			String token = this.k8sWatch.getK8s().getAuthToken();
			
			StringBuffer b = new StringBuffer();
			b.setLength(0);
			OpenUnisonConfigLoader.integrateIncludes(b,  (String)spec.get("className"));
			
			target.setClassName(b.toString());
			JSONArray params = (JSONArray) spec.get("params");
			for (Object o : params) {
				JSONObject param = (JSONObject) o;
				ParamType pt = new ParamType();
				b.setLength(0);
				OpenUnisonConfigLoader.integrateIncludes(b,(String) param.get("name")  );
				pt.setName(b.toString());
				b.setLength(0);
				OpenUnisonConfigLoader.integrateIncludes(b,(String) param.get("value")  );
				pt.setValue(b.toString());
				target.getParams().getParam().add(pt);
			}
			
			
			JSONArray secretParams = (JSONArray) spec.get("secretParams");
			
			for (Object o : secretParams) {
				JSONObject secretParam = (JSONObject) o;
				String paramName = (String) secretParam.get("name");
				String secretName = (String) secretParam.get("secretName");
				String secretKey = (String) secretParam.get("secretKey");
				
				String secretValue = this.k8sWatch.getSecretValue(secretName, secretKey, token, nonwatchHttp);
				ParamType pt = new ParamType();
				pt.setName(paramName);
				pt.setValue(secretValue);
				target.getParams().getParam().add(pt);
				
			}
			
			
			JSONArray attrs = (JSONArray) spec.get("targetAttributes");
			for (Object o : attrs) {
				JSONObject attr = (JSONObject) o;
				TargetAttributeType ta = new TargetAttributeType();
				b.setLength(0);
				OpenUnisonConfigLoader.integrateIncludes(b,(String) attr.get("name"));
				ta.setName(b.toString());
				b.setLength(0);
				OpenUnisonConfigLoader.integrateIncludes(b,(String) attr.get("source"));
				ta.setSource(b.toString());
				ta.setSourceType((String) attr.get("sourceType"));
				ta.setTargetType((String) attr.get("targetType"));
				target.getTargetAttribute().add(ta);
			}
			
			
			
			synchronized (this.tremolo.getProvisioning().getTargets().getTarget()) {
				int found = -1;
				int ii = 0;
				for (TargetType tt : this.tremolo.getProvisioning().getTargets().getTarget()) {
					if (tt.getName().equals(target.getName())) {
						found = ii;
						break;
					}
					ii++;
				}
				
				if (found >= 0) {
					this.tremolo.getProvisioning().getTargets().getTarget().remove(found);
				}
				
				this.tremolo.getProvisioning().getTargets().getTarget().add(target);
			}
			
			return target;
			
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not add target '" + name + "'",e);
		}
		
		
	}

	@Override
	public void modifyObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
		JSONObject metadata = (JSONObject) item.get("metadata");
		String name = (String) metadata.get("name");
		logger.info("Replacing target '" + name + "'");
		
		TargetType target = this.createTarget(item, name);
		
		this.provisioningEngine.replaceTarget(cfgMgr, target);
		

	}

	@Override
	public void deleteObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
		JSONObject metadata = (JSONObject) item.get("metadata");
		String name = (String) metadata.get("name");
		logger.info("Deleting target '" + name + "'");
		
		
		synchronized (this.tremolo.getProvisioning().getTargets().getTarget()) {
			int found = -1;
			int ii = 0;
			for (TargetType tt : this.tremolo.getProvisioning().getTargets().getTarget()) {
				if (tt.getName().equals(name)) {
					found = ii;
					break;
				}
				ii++;
			}
			
			if (found >= 0) {
				this.tremolo.getProvisioning().getTargets().getTarget().remove(found);
			}
			
			
		}
		
		
		this.provisioningEngine.removeTarget(name);

	}

	@Override
	public void loadDynamicTargets(ConfigManager cfgMgr, ProvisioningEngine provisioningEngine,
			Map<String, Attribute> init) throws ProvisioningException {
		this.tremolo = cfgMgr.getCfg();
		String k8sTarget = 	init.get("k8starget").getValues().get(0);
		String namespace = init.get("namespace").getValues().get(0);
		String uri = "/apis/openunison.tremolo.io/v1/namespaces/" + namespace + "/targets";
		
		
		this.provisioningEngine = provisioningEngine;
		this.cfgMgr = cfgMgr;
		
		this.k8sWatch = new K8sWatcher(k8sTarget,namespace,uri,this,cfgMgr,provisioningEngine);
		
		this.k8sWatch.initalRun();

	}

}
