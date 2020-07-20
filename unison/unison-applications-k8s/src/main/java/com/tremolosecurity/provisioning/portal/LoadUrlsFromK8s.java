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
import com.tremolosecurity.provisioning.core.ProvisioningEngine;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.server.StopableThread;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;

public class LoadUrlsFromK8s implements DynamicPortalUrls,StopableThread {

	static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(LoadUrlsFromK8s.class.getName());
	
	private String k8sTarget;

	private String namespace;

	private String uri;

	private OpenShiftTarget k8s;
	
	private HashSet<String> resourceVersions;
	
	TremoloType tremolo;
	
	boolean keepRunning;
	
	@Override
	public void loadDynamicPortalUrls(ConfigManager cfgMgr, ProvisioningEngine provisioningEngine,Map<String, Attribute> init)
			throws ProvisioningException {
		this.tremolo = cfgMgr.getCfg();
		this.k8sTarget = 	init.get("k8starget").getValues().get(0);
		this.namespace = init.get("namespace").getValues().get(0);
		this.uri = "/apis/openunison.tremolo.io/v1/namespaces/" + this.namespace + "/portalurls";
		
		this.k8s = (OpenShiftTarget) provisioningEngine.getTarget(k8sTarget).getProvider();
		
		if (this.k8s == null) {
			throw new ProvisioningException("Target " + k8sTarget + " does not exist");
		}
		
		HttpCon http;
		try {
			http = this.k8s.createClient();
		} catch (Exception e1) {
			throw new ProvisioningException("Could not create http connection",e1);
		}
		
		this.resourceVersions = new HashSet<String>();
		
		try {
			String token = k8s.getAuthToken();
			String json = k8s.callWS(token, http, uri);
			
			JSONObject list = (JSONObject) new JSONParser().parse(json);
			JSONArray items = (JSONArray) list.get("items");
			
			if (items == null) {
				logger.error("Invalid JSON Response : '" + json + "'");
				return;
			}
			
			for (Object o : items) {
				addUrl(cfgMgr.getCfg(), o);
				
				
			}
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not get urls",e);
		} finally {
			try {
				http.getHttp().close();
			} catch (IOException e) {
				logger.warn(e);
			}
			http.getBcm().close();
		}
		
		this.keepRunning = true;
		logger.info("Adding stoppable thread");
		GlobalEntries.getGlobalEntries().getConfigManager().addThread(this);
		logger.info("Starting watch");
		new Thread(this).start();

	}
	
	private void addUrl(TremoloType tremolo,Object o) {
		JSONObject trustObj = (JSONObject) o;
		JSONObject metadata = (JSONObject) trustObj.get("metadata");
		
		
		String resourceVersion = (String) metadata.get("resourceVersion");
		
		if (this.resourceVersions.contains(resourceVersion)) {
			logger.info("Resource " + resourceVersion + " already processed, skipping");
			return;
		}
		
		this.resourceVersions.add(resourceVersion);
		
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
	public void run() {
		logger.info("Starting watch");
		while (this.keepRunning) {
			HttpCon http;
			try {
				http = this.k8s.createClient();
			} catch (Exception e1) {
				logger.error("Could not create connection",e1);
				return;
			}
			
			try {
				String url = new StringBuilder().append(this.k8s.getUrl())
						                        .append(this.uri)
						                        .append("?watch=true&timeoutSeconds=10").toString();
				logger.info("watching " + url);
				HttpGet get = new HttpGet(url);
				get.setHeader("Authorization", new StringBuilder().append("Bearer ").append(this.k8s.getAuthToken()).toString());
				HttpResponse resp = http.getHttp().execute(get);
				BufferedReader in = new BufferedReader(new InputStreamReader(resp.getEntity().getContent()));
				String line = null;
				
				HttpCon nonwatchHttp = this.k8s.createClient();
				
				while ((line = in.readLine()) != null) {
					JSONObject event = (JSONObject) new JSONParser().parse(line);
					String action = (String) event.get("type");
					JSONObject trust = (JSONObject) event.get("object");
					
					
					
					if (action.equalsIgnoreCase("ADDED") || action.equalsIgnoreCase("MODIFIED")) {
						this.addUrl(tremolo,trust);
					} else {
						//deleted
						JSONObject metadata = (JSONObject) trust.get("metadata");
						String name = (String) metadata.get("name");
						logger.info("Deleting trust " + name);
						
						deleteUrl(tremolo, name);
					}
				}
				
				nonwatchHttp.getHttp().close();
				nonwatchHttp.getBcm().close();
				
			} catch (Exception e) {
				logger.error("Could not get authentication token",e);
				return;
			} finally {
				if (http != null) {
					try {
						http.getHttp().close();
					} catch (IOException e) {
						
					}
					http.getBcm().close();
				}
			}
		}
		
	}

	@Override
	public void stop() {
		this.keepRunning = false;
		
	}

}
