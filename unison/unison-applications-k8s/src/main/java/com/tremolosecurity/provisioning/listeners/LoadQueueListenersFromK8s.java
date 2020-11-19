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
package com.tremolosecurity.provisioning.listeners;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import javax.jms.JMSException;

import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.methods.HttpGet;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.AzRuleType;
import com.tremolosecurity.config.xml.AzRulesType;
import com.tremolosecurity.config.xml.MessageListenerType;
import com.tremolosecurity.config.xml.ParamType;
import com.tremolosecurity.config.xml.PortalUrlType;
import com.tremolosecurity.config.xml.TremoloType;
import com.tremolosecurity.idp.providers.OpenIDConnectTrust;
import com.tremolosecurity.k8s.watch.K8sWatchTarget;
import com.tremolosecurity.k8s.watch.K8sWatcher;
import com.tremolosecurity.openunison.util.config.OpenUnisonConfigLoader;
import com.tremolosecurity.provisioning.core.ProvisioningEngine;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.server.StopableThread;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;

public class LoadQueueListenersFromK8s implements DynamicQueueListeners,K8sWatchTarget {

	static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(LoadQueueListenersFromK8s.class.getName());
	
	
	TremoloType tremolo;
	
	K8sWatcher k8sWatch;


	private ConfigManager cfgMgr;
	
	
	@Override
	public void loadDynamicQueueListeners(ConfigManager cfgMgr, ProvisioningEngine provisioningEngine,Map<String, Attribute> init)
			throws ProvisioningException {
		this.tremolo = cfgMgr.getCfg();
		this.cfgMgr = cfgMgr;
		String k8sTarget = 	init.get("k8starget").getValues().get(0);
		String namespace = init.get("namespace").getValues().get(0);
		String uri = "/apis/openunison.tremolo.io/v1/namespaces/" + namespace + "/messagelisteners";
		
		this.k8sWatch = new K8sWatcher(k8sTarget,namespace,uri,this,cfgMgr,provisioningEngine);	
		this.k8sWatch.initalRun();
		
		

	}
	
	
	
	

	

	@Override
	public void addObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
		JSONObject metadata = (JSONObject) item.get("metadata");
		String name = (String) metadata.get("name");
		logger.info("Creating queue listener '" + name + "'");
		this.createQueue(cfg, name,item);
		
	}

	@Override
	public void modifyObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
		JSONObject metadata = (JSONObject) item.get("metadata");
		String name = (String) metadata.get("name");
		logger.info("Replacing queue listener '" + name + "'");
		this.deleteQueue(cfg, name,item);
		this.createQueue(cfg, name,item);
		
	}

	@Override
	public void deleteObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
		JSONObject metadata = (JSONObject) item.get("metadata");
		String name = (String) metadata.get("name");
		logger.info("Deleting queueListener " + name);
		
		this.deleteQueue(cfg, name,item);
		
	}
	
	private void createQueue(TremoloType tremolo,String name,JSONObject item) {
		JSONObject spec = (JSONObject) item.get("spec");
		MessageListenerType mlt = new MessageListenerType();
		mlt.setQueueName(name);
	
		StringBuffer b = new StringBuffer();
		
		b.setLength(0);
		OpenUnisonConfigLoader.integrateIncludes(b,(String) spec.get("className")  );
		mlt.setClassName(b.toString());
		
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
			
			mlt.getParams().add(pt);
			
			
			
			
		}
		
		try {
			this.cfgMgr.getProvisioningEngine().addMessageListener(mlt);
		} catch (InstantiationException | IllegalAccessException | ClassNotFoundException | ProvisioningException
				| JMSException e) {
			logger.warn("Could not create listener " + name,e);
		}
		
	}
	
	private void deleteQueue(TremoloType tremolo,String name,JSONObject item) {
		this.cfgMgr.getProvisioningEngine().removeMessageListener(name);
	}

}
