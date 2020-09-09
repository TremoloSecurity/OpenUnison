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
package com.tremolosecurity.k8s.watch;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashSet;

import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.methods.HttpGet;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningEngine;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.orgs.LoadOrgsFromK8s;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.server.StopableThread;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;

public class K8sWatcher implements StopableThread {
	static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(K8sWatcher.class.getName());
	
	private String k8sTarget;

	private String namespace;

	private String uri;

	
	
	private HashSet<String> resourceVersions;
	
	boolean keepRunning;
	
	K8sWatchTarget watchee;

	private ConfigManager cfgMgr;

	private ProvisioningEngine provisioningEngine;
	
	public K8sWatcher(String k8sTarget,String namespace, String uri,K8sWatchTarget watchTarget,ConfigManager cfgMgr, ProvisioningEngine provisioningEngine) {
		this.k8sTarget = k8sTarget;
		this.namespace = namespace;
		this.uri = uri;
		this.watchee = watchTarget;
		this.cfgMgr = cfgMgr;
		this.provisioningEngine = provisioningEngine;
		
	}
	
	public void initalRun() throws ProvisioningException {
		
		OpenShiftTarget k8s = (OpenShiftTarget) provisioningEngine.getTarget(k8sTarget).getProvider();
		
		if (k8s == null) {
			throw new ProvisioningException("Target " + k8sTarget + " does not exist");
		}
		
		HttpCon http;
		try {
			http = k8s.createClient();
		} catch (Exception e1) {
			throw new ProvisioningException("Could not create http connection",e1);
		}
		
		this.resourceVersions = new HashSet<String>();
		
		try {
			String token = k8s.getAuthToken(); 
			String json = null;
			try {
				json = k8s.callWS(token, http, uri);
			} catch (HttpResponseException e) {
				logger.warn("Could not retrieve urls, dynamic urls will not be supported",e);
				return;
			}
			
			JSONObject list = (JSONObject) new JSONParser().parse(json);
			JSONArray items = (JSONArray) list.get("items");
			
			if (items == null) {
				logger.error("Invalid JSON Response : '" + json + "'");
				return;
			}
			
			for (Object o : items) {
				JSONObject jsonObj = (JSONObject) o;
				JSONObject metadata = (JSONObject) jsonObj.get("metadata");
				
				
				String resourceVersion = (String) metadata.get("resourceVersion");
				
				if (this.resourceVersions.contains(resourceVersion)) {
					logger.info("Resource " + resourceVersion + " already processed, skipping");
				} else {
					this.resourceVersions.add(resourceVersion);
					this.watchee.addObject(cfgMgr.getCfg(), (JSONObject) o);
				}
				
				
				
				
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
	
	
	public String getSecretValue(String secretName, String secretKey,String token,HttpCon http) throws ClientProtocolException, IOException, ProvisioningException, ParseException {
		String secretUri = "/api/v1/namespaces/" + namespace + "/secrets/" + secretName;
		String secretJson = this.getK8s().callWS(token, http, secretUri);
		JSONObject secret = (JSONObject) new JSONParser().parse(secretJson);
		
		JSONObject data = (JSONObject) secret.get("data");
		if (data == null) {
			logger.error("Invalid secret response for " + secretUri + " - " + secretJson);
			return null;
		}
		
		
		
		String secretData = (String) data.get(secretKey);
		
		if (secretData == null) {
			logger.error("Secret key " + secretKey + " does not exist");
			return null;
		}
		
		
		
		String decoded = new String(java.util.Base64.getDecoder().decode(secretData));
		
		return decoded;
	}

	@Override
	public void run() {
		logger.info("Starting watch");
		while (this.keepRunning) {
			HttpCon http;
			OpenShiftTarget k8s;
			try {
				k8s = (OpenShiftTarget) this.provisioningEngine.getTarget(k8sTarget).getProvider();
			} catch (ProvisioningException e2) {
				logger.error("Could not load target, stopping watch",e2);
				return;
			}
			try {
				
				http = k8s.createClient();
			} catch (Exception e1) {
				logger.error("Could not create connection",e1);
				return;
			}
			
			try {
				String url = new StringBuilder().append(k8s.getUrl())
						                        .append(this.uri)
						                        .append("?watch=true&timeoutSeconds=10").toString();
				logger.info("watching " + url);
				HttpGet get = new HttpGet(url);
				get.setHeader("Authorization", new StringBuilder().append("Bearer ").append(k8s.getAuthToken()).toString());
				HttpResponse resp = http.getHttp().execute(get);
				BufferedReader in = new BufferedReader(new InputStreamReader(resp.getEntity().getContent()));
				String line = null;
				
				HttpCon nonwatchHttp = k8s.createClient();
				
				while ((line = in.readLine()) != null) {
					JSONObject event = (JSONObject) new JSONParser().parse(line);
					String action = (String) event.get("type");
					JSONObject jsonObject = (JSONObject) event.get("object");
					
					JSONObject metadata = (JSONObject) jsonObject.get("metadata");
					
					
					String resourceVersion = (String) metadata.get("resourceVersion");
					
					if (this.resourceVersions.contains(resourceVersion)) {
						logger.info("Resource " + resourceVersion + " already processed, skipping");
					} else {
						this.resourceVersions.add(resourceVersion);
						if (action.equalsIgnoreCase("ADDED")) {
							
							this.watchee.addObject(this.cfgMgr.getCfg(),jsonObject);
						} else if (action.equalsIgnoreCase("MODIFIED")) {
							this.watchee.modifyObject(this.cfgMgr.getCfg(),jsonObject);
						}
						
						else {
							//deleted
							this.watchee.deleteObject(this.cfgMgr.getCfg(),jsonObject);
						}
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
	
	public OpenShiftTarget getK8s() throws ProvisioningException {
		return (OpenShiftTarget) this.provisioningEngine.getTarget(k8sTarget).getProvider();
	}
}
