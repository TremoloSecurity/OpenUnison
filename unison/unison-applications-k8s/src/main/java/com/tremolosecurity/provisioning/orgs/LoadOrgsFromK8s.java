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
package com.tremolosecurity.provisioning.orgs;

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
import com.tremolosecurity.config.xml.OrgType;
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

public class LoadOrgsFromK8s implements DynamicOrgs,StopableThread {

	static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(LoadOrgsFromK8s.class.getName());
	
	private String k8sTarget;

	private String namespace;

	private String uri;

	private OpenShiftTarget k8s;
	
	private HashSet<String> resourceVersions;
	
	TremoloType tremolo;
	
	boolean keepRunning;
	
	Map<String,OrgType> orphanes;
	
	@Override
	public void loadDynamicOrgs(ConfigManager cfgMgr, ProvisioningEngine provisioningEngine,Map<String, Attribute> init)
			throws ProvisioningException {
		this.tremolo = cfgMgr.getCfg();
		this.k8sTarget = 	init.get("k8starget").getValues().get(0);
		this.namespace = init.get("namespace").getValues().get(0);
		this.uri = "/apis/openunison.tremolo.io/v1/namespaces/" + this.namespace + "/orgs";
		this.orphanes = new HashMap<String,OrgType>();
		
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
				addOrg(cfgMgr.getCfg(), o);
				
				
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
	
	private void addOrg(TremoloType tremolo,Object o) {
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
		
		OrgType org = new OrgType();
		
		
		
		
		org.setName((String) metadata.get("name")); 
		org.setDescription((String) spec.get("description"));
		org.setUuid((String) spec.get("uuid"));
		org.setShowInPortal(((Boolean) spec.get("showInPortal")));
		org.setShowInReports(((Boolean) spec.get("showInReports")));
		org.setShowInRequestsAccess(((Boolean) spec.get("showInRequestAccess")));
		org.setAzRules(new AzRulesType());
		
		String parentId = (String) spec.get("parent");
		
		
		
		
		
		JSONArray rules = (JSONArray) spec.get("azRules");
		for (Object orr : rules) {
			JSONObject rule = (JSONObject) orr;
			AzRuleType art = new AzRuleType();
			art.setScope((String) rule.get("scope"));
			art.setConstraint((String) rule.get("constraint"));
			org.getAzRules().getRule().add(art);
		}
		
		OrgType parent = this.findById(parentId, tremolo.getProvisioning().getOrg());
		
		if (parent == null) {
			for (String oid : this.orphanes.keySet()) {
				OrgType orphan = this.orphanes.get(oid);
				parent = this.findById(parentId, orphan);
				if (parent != null) {
					break;
				}
			}
		}
		
		if (parent == null) {
			
			OrgType oot = new OrgType();
			oot.setUuid(parentId);
			oot.setAzRules(new AzRulesType());
			oot.getOrgs().add(org);
			this.orphanes.put(parentId,oot);
			
		} else {
			OrgType toRemove = null;
			for (OrgType oot : parent.getOrgs()) {
				if (oot.getUuid().contentEquals(org.getUuid())) {
					org.getOrgs().addAll(oot.getOrgs());
					toRemove = oot;
				}
			}
			
			if (toRemove != null) {
				parent.getOrgs().remove(toRemove);
			}
			parent.getOrgs().add(org);
		}
		
		
		if (this.orphanes.containsKey(org.getUuid())) {
			OrgType oot = this.orphanes.remove(org.getUuid());
			org.getOrgs().addAll(oot.getOrgs());
		}
		
		
	}

	private OrgType findById(String id,OrgType ot) {
		if (ot.getUuid().contentEquals(id)) {
			return ot;
		} else {
			if (ot.getOrgs() != null) {
				for (OrgType subOt : ot.getOrgs()) {
					OrgType subSubOt = findById(id,subOt);
					if (subSubOt != null) {
						return subSubOt;
					}
				}
			}
		}
		
		return null;
	}
	
	private void findParentByChildId(String id,OrgType ot,OrgTypeHolder parentHolder) {
		if (ot.getOrgs() != null) {
			for (OrgType oot : ot.getOrgs()) {
				if (oot.getUuid().contentEquals(id)) {
					parentHolder.parent = ot;
					return;
				} else {
					this.findParentByChildId(id, oot, parentHolder);
					if (parentHolder.parent != null) {
						return;
					}
				}
			}
		}
		
		
	}
	
	private void deleteOrg(TremoloType tremolo, String orgId) {
		logger.info("deleting " + orgId);
	
		OrgTypeHolder oth = new OrgTypeHolder();
		this.findParentByChildId(orgId, tremolo.getProvisioning().getOrg(),oth);
		OrgType parent = oth.parent;
		
		if (parent == null) {
			for (String oid : this.orphanes.keySet()) {
				OrgType orphan = this.orphanes.get(oid);
				this.findParentByChildId(orgId, orphan,oth);
				if (oth.parent != null) {
					parent = oth.parent;
					break;
				}
			}
		}
		
		
		logger.info("Found parent : " + parent);
		logger.info("found parent id : " + parent.getUuid());
		OrgType ot = this.findById(orgId, parent);
		logger.info("found ot : " + ot);
		if (parent != null) {
			logger.info("before remove : " + parent.getOrgs());
			logger.info("removing");
			parent.getOrgs().remove(ot);
			logger.info("after remove : " + parent.getOrgs());
		} 
		
		this.orphanes.put(ot.getUuid(),ot);
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
						this.addOrg(tremolo,trust);
					} else {
						//deleted
						JSONObject metadata = (JSONObject) trust.get("metadata");
						String name = (String) metadata.get("name");
						JSONObject spec = (JSONObject) trust.get("spec");
						String uuid = (String) spec.get("uuid");
						logger.info("Deleting organization " + uuid);
						
						deleteOrg(tremolo, uuid);
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

class OrgTypeHolder {
	OrgType parent;
}
