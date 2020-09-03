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
import com.tremolosecurity.k8s.watch.K8sWatchTarget;
import com.tremolosecurity.k8s.watch.K8sWatcher;
import com.tremolosecurity.provisioning.core.ProvisioningEngine;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.server.StopableThread;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;

public class LoadOrgsFromK8s implements DynamicOrgs,K8sWatchTarget {

	static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(LoadOrgsFromK8s.class.getName());
	
	K8sWatcher k8sWatch;
	
	TremoloType tremolo;
	Map<String,OrgType> orphanes;
	
	
	@Override
	public void loadDynamicOrgs(ConfigManager cfgMgr, ProvisioningEngine provisioningEngine,Map<String, Attribute> init)
			throws ProvisioningException {
		this.tremolo = cfgMgr.getCfg();
		String k8sTarget = 	init.get("k8starget").getValues().get(0);
		String namespace = init.get("namespace").getValues().get(0);
		String uri = "/apis/openunison.tremolo.io/v1/namespaces/" + namespace + "/orgs";
		
		
		this.orphanes = new HashMap<String,OrgType>();
		
		this.k8sWatch = new K8sWatcher(k8sTarget,namespace,uri,this,cfgMgr,provisioningEngine);
		
		this.k8sWatch.initalRun();
		
		

	}
	
	private void addOrg(TremoloType tremolo,Object o) {
		JSONObject trustObj = (JSONObject) o;
		JSONObject metadata = (JSONObject) trustObj.get("metadata");
		
		
		
		
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
			
			this.deleteOrg(tremolo, org.getUuid());
			
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
		
		
		
		
		if (parent != null) {
			OrgType ot = this.findById(orgId, parent);
			parent.getOrgs().remove(ot);
			this.orphanes.put(ot.getUuid(),ot);
		} 
		
		
	}

	


	@Override
	public void addObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
		this.addOrg(cfg, item);
		
	}

	@Override
	public void modifyObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
		this.addOrg(cfg, item);
		
	}

	@Override
	public void deleteObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
		JSONObject metadata = (JSONObject) item.get("metadata");
		String name = (String) metadata.get("name");
		JSONObject spec = (JSONObject) item.get("spec");
		String uuid = (String) spec.get("uuid");
		logger.info("Deleting organization " + uuid);
		
		deleteOrg(tremolo, uuid);
		
	}
	

}

class OrgTypeHolder {
	OrgType parent;
}
