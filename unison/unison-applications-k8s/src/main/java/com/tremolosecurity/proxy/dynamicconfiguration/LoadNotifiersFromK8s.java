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
package com.tremolosecurity.proxy.dynamicconfiguration;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.NotificationType;
import com.tremolosecurity.config.xml.OrgType;
import com.tremolosecurity.config.xml.ParamType;
import com.tremolosecurity.config.xml.TargetAttributeType;
import com.tremolosecurity.config.xml.TargetConfigType;
import com.tremolosecurity.config.xml.TargetType;
import com.tremolosecurity.config.xml.TremoloType;
import com.tremolosecurity.k8s.watch.K8sWatchTarget;
import com.tremolosecurity.k8s.watch.K8sWatcher;
import com.tremolosecurity.openunison.notifications.DynamicNotifiers;
import com.tremolosecurity.openunison.util.config.OpenUnisonConfigLoader;
import com.tremolosecurity.provisioning.core.ProvisioningEngine;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.targets.DynamicTargets;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;

public class LoadNotifiersFromK8s implements DynamicNotifiers, K8sWatchTarget {
	
	static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(LoadNotifiersFromK8s.class.getName());
	
	K8sWatcher k8sWatch;
	
	TremoloType tremolo;

	private ProvisioningEngine provisioningEngine;
	private ConfigManager cfgMgr;

	@Override
	public void addObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
		
		JSONObject metadata = (JSONObject) item.get("metadata");
		String name = (String) metadata.get("name");
		logger.info("Creating notifier '" + name + "'");
		NotificationType target = this.createNotification(item, name);
		
		try {
			this.cfgMgr.getNotificationsMananager().addNotificationSystem(target.getName(), target.getClassName(), pt2attrs(target.getParams()));
		} catch (Exception e) {
			throw new ProvisioningException(String.format("Could not add notification %s",target.getName()),e);
		}
		
		
	}

	private NotificationType createNotification(JSONObject item, String name) throws ProvisioningException {
		NotificationType notification = new NotificationType();
		notification.setName(name);
		
		HttpCon nonwatchHttp = null;
		
		JSONObject spec = (JSONObject) item.get("spec");
		try {
			
			nonwatchHttp = this.k8sWatch.getK8s().createClient();
			String token = this.k8sWatch.getK8s().getAuthToken();
			
			StringBuffer b = new StringBuffer();
			b.setLength(0);
			OpenUnisonConfigLoader.integrateIncludes(b,  (String)spec.get("className"));
			
			notification.setClassName(b.toString());
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
				notification.getParams().add(pt);
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
				notification.getParams().add(pt);
				
			}
			
			return notification;
			
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not add notification '" + name + "'",e);
		} finally {
			if (nonwatchHttp != null) {
				try {
					nonwatchHttp.getHttp().close();
				} catch (IOException e) {
					
				}
				nonwatchHttp.getBcm().close();
			}
		}
		
		
	}
	
	private Map<String,Attribute> pt2attrs(List<ParamType> pts) {
		Map<String,Attribute> attrs = new HashMap<String,Attribute>();
		for (ParamType pt : pts) {
			Attribute attr = attrs.get(pt.getName());
			if (attr == null) {
				attr = new Attribute(pt.getName());
				attrs.put(pt.getName(), new Attribute(pt.getName()));
			}
			attr.getValues().add(pt.getValue());
		}
		return attrs;
	}

	@Override
	public void modifyObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
		JSONObject metadata = (JSONObject) item.get("metadata");
		String name = (String) metadata.get("name");
		logger.info("Replacing notifier '" + name + "'");
		
		NotificationType target = this.createNotification(item, name);
		
		try {
			this.cfgMgr.getNotificationsMananager().addNotificationSystem(target.getName(), target.getClassName(), pt2attrs(target.getParams()));
		} catch (Exception e) {
			throw new ProvisioningException(String.format("Could not modify notification %s",target.getName()),e);
		}
		

	}

	@Override
	public void deleteObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
		JSONObject metadata = (JSONObject) item.get("metadata");
		String name = (String) metadata.get("name");
		logger.info("Deleting target '" + name + "'");
		
		
		this.cfgMgr.getNotificationsMananager().removeNotificationSystem(name);

	}

	@Override
	public void loadDynamicNotifiers(ConfigManager cfgMgr, ProvisioningEngine provisioningEngine,
			Map<String, Attribute> init) throws ProvisioningException {
		this.tremolo = cfgMgr.getCfg();
		String k8sTarget = 	init.get("k8starget").getValues().get(0);
		String namespace = init.get("namespace").getValues().get(0);
		
		
		
		this.provisioningEngine = provisioningEngine;
		this.cfgMgr = cfgMgr;
		
		this.k8sWatch = new K8sWatcher(k8sTarget,namespace,"notifiers","openunison.tremolo.io",this,cfgMgr,provisioningEngine);
		
		this.k8sWatch.initalRun();

	}

}
