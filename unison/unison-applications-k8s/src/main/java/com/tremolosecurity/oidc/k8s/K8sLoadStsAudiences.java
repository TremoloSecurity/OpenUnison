/*******************************************************************************
 * Copyright 2020 Tremolo Security, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/

package com.tremolosecurity.oidc.k8s;

import com.tremolosecurity.config.xml.TremoloType;
import com.tremolosecurity.idp.providers.OpenIDConnectIdP;
import com.tremolosecurity.idp.providers.OpenIDConnectTrust;
import com.tremolosecurity.idp.providers.oidc.trusts.DynamicLoadStsAudiences;
import com.tremolosecurity.idp.providers.oidc.trusts.DynamicLoadTrusts;
import com.tremolosecurity.k8s.watch.K8sWatchTarget;
import com.tremolosecurity.k8s.watch.K8sWatcher;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.mapping.MapIdentity;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.proxy.az.AzRule;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import jakarta.servlet.ServletContext;
import org.apache.http.client.ClientProtocolException;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.StringTokenizer;

public class K8sLoadStsAudiences implements DynamicLoadStsAudiences,K8sWatchTarget {
	
	static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(K8sLoadStsAudiences.class.getName());

	String idpName;
	OpenIDConnectIdP idp;
	HashMap<String, OpenIDConnectTrust> trusts;
	String namespace;
	
	K8sWatcher k8sWatch;

	
	@Override
	public void loadAudiences(String idpName,ServletContext ctx, HashMap<String, Attribute> init, OpenIDConnectIdP idp) throws Exception {
		this.idpName = idpName;
		this.idp = idp;

		
		String k8sTarget = 	init.get("trusts.k8starget").getValues().get(0);
		this.namespace = init.get("trusts.namespace").getValues().get(0);
		
		
		this.k8sWatch = new K8sWatcher(k8sTarget,namespace,"stsaudiences","openunison.tremolo.io",this,GlobalEntries.getGlobalEntries().getConfigManager(),GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine());
		this.k8sWatch.initalRun();
		
		
		
	}
	
	

	private void addAudiences(HttpCon http, String token, Object o)
			throws IOException, ClientProtocolException, ParseException,ProvisioningException {



		JSONObject audObj = (JSONObject) o;
		JSONObject metadata = (JSONObject) audObj.get("metadata");
		String stsAudName = (String) metadata.get("name");
		JSONObject spec = (JSONObject) audObj.get("spec");
		String clientid = spec.get("clientId").toString();
		List<String> audiences = new ArrayList<String>();
		JSONArray audArray = (JSONArray) spec.get("audiences");
		audiences.addAll(audArray);

		boolean expectsLabel = idp.getLabelValue() != null;

		JSONObject labels = (JSONObject) metadata.get("labels");
		String filterLabel = null;
		if (labels != null) {
			filterLabel = (String) labels.get("tremolo.io/trust-app");
		}

		if (expectsLabel) {
			// expecting a label
			if (filterLabel == null) {
				// there's no label, skip
				// remove first if it exists
				idp.removeAudiences(stsAudName);
				return;
			} else {
				if (! filterLabel.equals(idp.getLabelValue())) {
					// the filter labels don't match, skip
					// remove first if it exists
					idp.removeAudiences(stsAudName);
					return;
				}
			}
		} else {
			// not expecting a label
			if (filterLabel != null) {
				// there is a label, ignore it
				// remove first if it exists
				idp.removeAudiences(stsAudName);
				return;
			}
		}
		
		String resourceVersion = (String) metadata.get("resourceVersion");

		

		logger.info(metadata.get("name"));
		
		
		idp.addAudiences(stsAudName,clientid,audiences);
	}

	

	@Override
	public void addObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
		try {
			HttpCon nonwatchHttp = this.k8sWatch.getK8s().createClient();
			this.addAudiences(nonwatchHttp, this.k8sWatch.getK8s().getAuthToken(), item);
			nonwatchHttp.getHttp().close();
			nonwatchHttp.getBcm().close();
		} catch (Exception e) {
			throw new ProvisioningException("Could not add sts audience",e);
		}
		
		
	}

	@Override
	public void modifyObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
		try {
			HttpCon nonwatchHttp = this.k8sWatch.getK8s().createClient();
			this.addAudiences(nonwatchHttp, this.k8sWatch.getK8s().getAuthToken(), item);
			nonwatchHttp.getHttp().close();
			nonwatchHttp.getBcm().close();
		} catch (Exception e) {
			throw new ProvisioningException("Could not sts audience",e);
		}
		
	}

	@Override
	public void deleteObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
		//deleted
		JSONObject metadata = (JSONObject) item.get("metadata");
		String name = (String) metadata.get("name");
		logger.info("Deleting audience " + name);
		JSONObject spec = (JSONObject) item.get("spec");
		String clientId = (String) spec.get("clientId");
		List<String> audiences = new ArrayList<String>();
		JSONArray audArray = (JSONArray) spec.get("audiences");
		audiences.addAll(audArray);
		idp.removeAudiences(name);
		
	}

}
