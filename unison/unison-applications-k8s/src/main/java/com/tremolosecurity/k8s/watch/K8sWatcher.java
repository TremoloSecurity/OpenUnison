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
import java.net.SocketException;
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
import com.tremolosecurity.openunison.util.config.OpenUnisonConfigLoader;
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

	private String plural;

	private String group;
	
	private String lastResourceId;
	
	
	public K8sWatcher(String k8sTarget,String namespace, String plural, String group,K8sWatchTarget watchTarget,ConfigManager cfgMgr, ProvisioningEngine provisioningEngine) {
		this.k8sTarget = k8sTarget;
		this.namespace = namespace;
		
		this.plural = plural;
		this.group = group;
		
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
			
			this.uri = this.findCrdUri(token, http, k8s);
			
			
			try {
				json = k8s.callWS(token, http, uri);
			} catch (HttpResponseException e) {
				logger.warn("Could not retrieve urls, dynamic urls will not be supported",e);
				return;
			}
			
			
			
			
			
			
			
			
			JSONObject list = (JSONObject) new JSONParser().parse(json);
			JSONObject listmetadata = (JSONObject) list.get("metadata");
			
			if (listmetadata != null) {
				this.lastResourceId = (String) listmetadata.get("resourceVersion");
				logger.info(String.format("Starting watch at %s",this.lastResourceId));
			}
			
			JSONArray items = (JSONArray) list.get("items");
			
			if (items == null) {
				logger.error("Invalid JSON Response : '" + json + "'");
				return;
			}
			
			for (Object o : items) {
				JSONObject jsonObj = (JSONObject) o;
				
				String strjson = jsonObj.toString();
				
				if (logger.isDebugEnabled()) logger.debug("json before includes : " + strjson);
				
				StringBuffer b = new StringBuffer();
				b.setLength(0);
				OpenUnisonConfigLoader.integrateIncludes(b,  strjson);
				
				if (logger.isDebugEnabled()) logger.debug("json after includes : " + b.toString());
				
				jsonObj = (JSONObject) new JSONParser().parse(b.toString());
				
				JSONObject metadata = (JSONObject) jsonObj.get("metadata");
				
				
				String resourceVersion = (String) metadata.get("resourceVersion");
				
				if (this.resourceVersions.contains(resourceVersion)) {
					logger.info("Resource " + resourceVersion + " already processed, skipping");
				} else {
					this.resourceVersions.add(resourceVersion);
					this.watchee.addObject(cfgMgr.getCfg(), jsonObj);
				}
				
				
				
				
			}
			
		} catch (Throwable e) {
			throw new ProvisioningException("Could not load CRDs",e);
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
	
	private String findCrdUri(String token,HttpCon http,OpenShiftTarget k8s) throws ClientProtocolException, IOException, ParseException {
		StringBuilder sb = new StringBuilder();
		sb.append("/apis/apiextensions.k8s.io/v1/customresourcedefinitions/").append(plural).append('.').append(group);
		String crdUrl = sb.toString();
		
		String crdJson = k8s.callWS(token, http, crdUrl);
		JSONObject root = (JSONObject) new JSONParser().parse(crdJson);
		
		JSONObject spec = (JSONObject)  root.get("spec");
		
		String apiVersion = "";
		
		if (spec == null) {
			// haven't yet upgraded the operator, assume v1
			apiVersion = "v1";
		} else {
		
			JSONArray versions = (JSONArray) spec.get("versions");
			
			
			
			for (Object v : versions) {
				JSONObject version = (JSONObject) v;
				boolean served = (Boolean) version.get("served");
				boolean stored = (Boolean) version.get("storage");
				
				if (served && stored) {
					apiVersion = (String) version.get("name");
				}
			}
		}
		
		sb.setLength(0);
		sb.append("/apis/").append(group).append("/").append(apiVersion).append("/namespaces/").append(namespace).append("/").append(plural);
		return sb.toString();
		
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
			
			OpenShiftTarget k8s;
			try {
				k8s = (OpenShiftTarget) this.provisioningEngine.getTarget(k8sTarget).getProvider();
			} catch (ProvisioningException e2) {
				logger.error("Could not load target, stopping watch",e2);
				return;
			}
			
			runWatch(k8s);
		}
		
	}

	private void runWatch(OpenShiftTarget k8s) {
		HttpCon http;
		try {
			
			http = k8s.createClient();
		} catch (Exception e1) {
			logger.error("Could not create connection",e1);
			return;
		}
		
		try {
			StringBuilder urlb = new StringBuilder().append(k8s.getUrl())
					                        .append(this.uri)
					                        .append("?watch=true&timeoutSecond=25&allowWatchBookmarks=true");
			
			if (this.lastResourceId != null) {
				urlb.append("&resourceVersion=")
				   .append(this.lastResourceId).toString();
			}
			
			String url = urlb.toString();
					                        
			
			logger.info("watching " + url);
			HttpGet get = new HttpGet(url);
			get.setHeader("Authorization", new StringBuilder().append("Bearer ").append(k8s.getAuthToken()).toString());
			HttpResponse resp = http.getHttp().execute(get);
			
			if (resp.getStatusLine().getStatusCode() == 504 || resp.getStatusLine().getStatusCode() == 410) {
				logger.info("invalid resource error: " + resp.getStatusLine().getReasonPhrase());
				this.lastResourceId = null;
			}
			
			BufferedReader in = new BufferedReader(new InputStreamReader(resp.getEntity().getContent()));
			String line = null;
			
			HttpCon nonwatchHttp = k8s.createClient();
			
			while ((line = in.readLine()) != null) {
				JSONObject event = (JSONObject) new JSONParser().parse(line);
				String action = (String) event.get("type");
				JSONObject jsonObject = (JSONObject) event.get("object");
				
				String strjson = jsonObject.toString();
				
				if (logger.isDebugEnabled()) logger.debug("json before includes : " + strjson);
				
				StringBuffer b = new StringBuffer();
				b.setLength(0);
				OpenUnisonConfigLoader.integrateIncludes(b,  strjson);
				
				if (logger.isDebugEnabled()) logger.debug("json after includes : " + b.toString());
				
				jsonObject = (JSONObject) new JSONParser().parse(b.toString());
				
				JSONObject metadata = (JSONObject) jsonObject.get("metadata");
				
				
				String resourceVersion = (String) metadata.get("resourceVersion");
				
				
				if (action.equalsIgnoreCase("ERROR")) {
					// there was an error
					long errorCode = (Long) jsonObject.get("code");
					
					if (errorCode == 504 || errorCode == 410) {
						String msg = (String) jsonObject.get("message");
						int indexstart = msg.indexOf('(');
						if (indexstart == -1) {
							//i'm not really sure how to handle this
							throw new Exception(String.format("Could not process watch %s",msg));
						} else {
							int indexend = msg.indexOf(')');
							String newResourceId = msg.substring(indexstart+1,indexend);
							this.resourceVersions.add(newResourceId);
							this.lastResourceId = newResourceId;
						}
					}
					
				} else if (this.resourceVersions.contains(resourceVersion)) {
					logger.info("Resource " + resourceVersion + " already processed, skipping");
				} else if (action.equalsIgnoreCase("BOOKMARK")) {
					this.resourceVersions.add(resourceVersion);
					this.lastResourceId = resourceVersion;
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
					
					this.lastResourceId = resourceVersion;
				}
			}
			
			nonwatchHttp.getHttp().close();
			nonwatchHttp.getBcm().close();
			
		} catch (SocketException se) {
			logger.warn("Connection to api server reset, restarting");
			
			return;
		} catch (Throwable e) {
			logger.warn("Could not run watch, restarting",e);
			
			
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
		return;
	}

	@Override
	public void stop() {
		this.keepRunning = false;
		
	}
	
	public OpenShiftTarget getK8s() throws ProvisioningException {
		return (OpenShiftTarget) this.provisioningEngine.getTarget(k8sTarget).getProvider();
	}
}
