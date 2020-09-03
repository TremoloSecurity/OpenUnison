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
package com.tremolosecurity.provisioning.portal;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

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
import com.tremolosecurity.config.xml.PortalUrlType;
import com.tremolosecurity.config.xml.TremoloType;
import com.tremolosecurity.idp.providers.OpenIDConnectTrust;
import com.tremolosecurity.k8s.watch.K8sWatchTarget;
import com.tremolosecurity.k8s.watch.K8sWatcher;
import com.tremolosecurity.provisioning.core.ProvisioningEngine;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.server.StopableThread;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;

public class LoadUrlsFromK8s implements DynamicPortalUrls,K8sWatchTarget {

	static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(LoadUrlsFromK8s.class.getName());
	
	
	TremoloType tremolo;
	
	K8sWatcher k8sWatch;
	
	
	@Override
	public void loadDynamicPortalUrls(ConfigManager cfgMgr, ProvisioningEngine provisioningEngine,Map<String, Attribute> init)
			throws ProvisioningException {
		this.tremolo = cfgMgr.getCfg();
		String k8sTarget = 	init.get("k8starget").getValues().get(0);
		String namespace = init.get("namespace").getValues().get(0);
		String uri = "/apis/openunison.tremolo.io/v1/namespaces/" + namespace + "/portalurls";
		
		this.k8sWatch = new K8sWatcher(k8sTarget,namespace,uri,this,cfgMgr,provisioningEngine);	
		this.k8sWatch.initalRun();
		
		

	}
	
	private void addUrl(TremoloType tremolo,Object o) {
		JSONObject trustObj = (JSONObject) o;
		JSONObject metadata = (JSONObject) trustObj.get("metadata");
		
		
		String resourceVersion = (String) metadata.get("resourceVersion");
		
		
		JSONObject spec = (JSONObject) trustObj.get("spec");
		logger.info(metadata.get("name"));
		
		PortalUrlType portalUrl = new PortalUrlType();
		
		
		portalUrl.setName((String) metadata.get("name")); 
		portalUrl.setLabel((String) spec.get("label"));
		portalUrl.setOrg((String) spec.get("org"));
		portalUrl.setUrl((String) spec.get("url"));
		portalUrl.setIcon((String) spec.get("icon"));
		portalUrl.setAzRules(new AzRulesType());
		
		JSONArray rules = (JSONArray) spec.get("azRules");
		for (Object orr : rules) {
			JSONObject rule = (JSONObject) orr;
			AzRuleType art = new AzRuleType();
			art.setScope((String) rule.get("scope"));
			art.setConstraint((String) rule.get("constraint"));
			portalUrl.getAzRules().getRule().add(art);
		}
		
		
		
		synchronized(tremolo.getProvisioning().getPortal()) {
			deleteUrl(tremolo, portalUrl.getName());
			
			tremolo.getProvisioning().getPortal().getUrls().add(portalUrl);
		}
	}

	private void deleteUrl(TremoloType tremolo, String portalUrl) {
		PortalUrlType put = null;
		for (PortalUrlType pu : tremolo.getProvisioning().getPortal().getUrls()) {
			if (pu.getName().equalsIgnoreCase(portalUrl)) {
				put = pu;
				break;
			}
		}
		
		if (put != null ) {
			tremolo.getProvisioning().getPortal().getUrls().remove(put);
		}
	}

	

	@Override
	public void addObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
		this.addUrl(tremolo,item);
		
	}

	@Override
	public void modifyObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
		this.addUrl(tremolo,item);
		
	}

	@Override
	public void deleteObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
		JSONObject metadata = (JSONObject) item.get("metadata");
		String name = (String) metadata.get("name");
		logger.info("Deleting trust " + name);
		
		deleteUrl(tremolo, name);
		
	}

}
