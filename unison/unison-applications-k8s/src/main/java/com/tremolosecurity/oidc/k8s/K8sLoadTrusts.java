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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.HashSet;
import java.util.StringTokenizer;

import com.tremolosecurity.proxy.az.AzRule;
import jakarta.servlet.ServletContext;

import jakarta.servlet.ServletException;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.methods.HttpGet;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.tremolosecurity.config.xml.TremoloType;
import com.tremolosecurity.idp.providers.OpenIDConnectIdP;
import com.tremolosecurity.idp.providers.OpenIDConnectTrust;
import com.tremolosecurity.idp.providers.oidc.trusts.DynamicLoadTrusts;
import com.tremolosecurity.k8s.watch.K8sWatchTarget;
import com.tremolosecurity.k8s.watch.K8sWatcher;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.mapping.MapIdentity;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.server.StopableThread;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;

public class K8sLoadTrusts implements DynamicLoadTrusts,K8sWatchTarget {
	
	static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(K8sLoadTrusts.class.getName());
	
	HashMap<String, OpenIDConnectTrust> trusts;
	String namespace;
	
	K8sWatcher k8sWatch;

	
	@Override
	public void loadTrusts(String idpName, ServletContext ctx,
			HashMap<String, Attribute> init, HashMap<String, HashMap<String, Attribute>> trustCfg, MapIdentity mapper,HashMap<String, OpenIDConnectTrust> trusts)
			throws Exception {
		
		this.trusts = trusts;
		
		String k8sTarget = 	init.get("trusts.k8starget").getValues().get(0);
		this.namespace = init.get("trusts.namespace").getValues().get(0);
		
		
		this.k8sWatch = new K8sWatcher(k8sTarget,namespace,"trusts","openunison.tremolo.io",this,GlobalEntries.getGlobalEntries().getConfigManager(),GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine());	
		this.k8sWatch.initalRun();
		
		
		
	}
	
	

	private void addTrust(HashMap<String, OpenIDConnectTrust> trusts, HttpCon http, String token, Object o)
			throws IOException, ClientProtocolException, ParseException,ProvisioningException {
		JSONObject trustObj = (JSONObject) o;
		JSONObject metadata = (JSONObject) trustObj.get("metadata");
		
		
		String resourceVersion = (String) metadata.get("resourceVersion");

		
		JSONObject spec = (JSONObject) trustObj.get("spec");
		logger.info(metadata.get("name"));
		
		
		OpenIDConnectTrust trust = new OpenIDConnectTrust();
		trust.setClientID(spec.get("clientId").toString());
		trust.setPublicEndpoint((Boolean) spec.get("publicEndpoint"));
		
		if (! trust.isPublicEndpoint()) {
			JSONObject secretInfo = (JSONObject) spec.get("clientSecret");
			if (secretInfo == null) {
				logger.error("secretInfo not provided for trust " + metadata.get("name"));
				return;
			}
			
			
			String secretData = this.k8sWatch.getSecretValue(secretInfo.get("secretName").toString(), secretInfo.get("keyName").toString(), token, http);
			
			if (secretData == null) {
				logger.error("No secret found");
				return;
			}
			
			
			trust.setClientSecret(secretData);
		}
		
		JSONArray redirects = (JSONArray) spec.get("redirectURI");
		if (redirects != null) {
			trust.getRedirectURI().addAll(redirects);
		}

		trust.setCodeLastmileKeyName(spec.get("codeLastMileKeyName").toString());
		trust.setAuthChain(spec.get("authChainName").toString());
		trust.setCodeTokenTimeToLive((Long) spec.get("codeTokenSkewMilis"));
		trust.setAccessTokenTimeToLive((Long) spec.get("accessTokenTimeToLive"));
		trust.setAccessTokenSkewMillis((Long) spec.get("accessTokenSkewMillis"));

		
		trust.setSignedUserInfo((Boolean) spec.get("signedUserInfo"));
		trust.setVerifyRedirect((Boolean) spec.get("verifyRedirect"));
		
		
		trust.setTrustName(metadata.get("name").toString());

		// supports client credentials?
		Object val = spec.get("enableClientCredentialsGrant");
		if (val != null && val instanceof Boolean) {
			trust.setEnableClientCredentialGrant((Boolean) val);
		}

		// check for sts
		val = spec.get("isSts");
		if (val != null && val instanceof Boolean) {
			trust.setSts((Boolean) val);

			if (trust.isSts()) {
				val = spec.get("stsImpersonation");
				if (val != null && val instanceof Boolean) {
					trust.setStsImpersonation((Boolean) val);
				}

				val = spec.get("stsDelegation");
				if (val != null && val instanceof Boolean) {
					trust.setStsDelegation((Boolean) val);
				}

				val = spec.get("clientAzRules");
				if (val != null && val instanceof JSONArray) {
					JSONArray rules = (JSONArray) val;
					rules.forEach(ruleVal ->{
						String ruleCfg = (String) ruleVal;

						StringTokenizer toker = new StringTokenizer(ruleCfg,";",false);
						toker.hasMoreTokens();
						String scope = toker.nextToken();
						toker.hasMoreTokens();
						String constraint = toker.nextToken();

						try {
							AzRule rule = new AzRule(scope,constraint,null,GlobalEntries.getGlobalEntries().getConfigManager(),null);
							trust.getClientAzRules().add(rule);
						} catch (ProvisioningException e) {
							throw new RuntimeException(String.format("Could not create az rule '%s' for trust '%s'",ruleCfg,trust.getTrustName()),e);
						}

					});
				}


				val = spec.get("authorizedAudiences");
				if (val != null && val instanceof JSONArray) {
					JSONArray rules = (JSONArray) val;
					rules.forEach(ruleVal ->{
						trust.getAllowedAudiences().add(ruleVal.toString());
					});
				}

				val = spec.get("subjectAzRules");
				if (val != null && val instanceof JSONArray) {
					JSONArray rules = (JSONArray) val;
					rules.forEach(ruleVal ->{
						String ruleCfg = (String) ruleVal;

						StringTokenizer toker = new StringTokenizer(ruleCfg,";",false);
						toker.hasMoreTokens();
						String scope = toker.nextToken();
						toker.hasMoreTokens();
						String constraint = toker.nextToken();

						try {
							AzRule rule = new AzRule(scope,constraint,null,GlobalEntries.getGlobalEntries().getConfigManager(),null);
							trust.getSubjectAzRules().add(rule);
						} catch (ProvisioningException e) {
							throw new RuntimeException(String.format("Could not create az rule '%s' for trust '%s'",ruleCfg,trust.getTrustName()),e);
						}

					});
				}



			}
		}
		
		synchronized(trusts) {
			trusts.put(trust.getClientID(),trust);
		}
	}

	

	@Override
	public void addObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
		try {
			HttpCon nonwatchHttp = this.k8sWatch.getK8s().createClient();
			this.addTrust(trusts, nonwatchHttp, this.k8sWatch.getK8s().getAuthToken(), item);
			nonwatchHttp.getHttp().close();
			nonwatchHttp.getBcm().close();
		} catch (Exception e) {
			throw new ProvisioningException("Could not add trust",e);
		}
		
		
	}

	@Override
	public void modifyObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
		try {
			HttpCon nonwatchHttp = this.k8sWatch.getK8s().createClient();
			this.addTrust(trusts, nonwatchHttp, this.k8sWatch.getK8s().getAuthToken(), item);
			nonwatchHttp.getHttp().close();
			nonwatchHttp.getBcm().close();
		} catch (Exception e) {
			throw new ProvisioningException("Could not add trust",e);
		}
		
	}

	@Override
	public void deleteObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
		//deleted
		JSONObject metadata = (JSONObject) item.get("metadata");
		String name = (String) metadata.get("name");
		logger.info("Deleting trust " + name);
		JSONObject spec = (JSONObject) item.get("spec");
		String clientId = (String) spec.get("clientId");
		synchronized(trusts) {
			trusts.remove(clientId);
		}
		
	}

}
