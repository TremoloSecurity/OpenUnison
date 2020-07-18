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

import javax.servlet.ServletContext;

import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.HttpGet;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.tremolosecurity.idp.providers.OpenIDConnectIdP;
import com.tremolosecurity.idp.providers.OpenIDConnectTrust;
import com.tremolosecurity.idp.providers.oidc.trusts.DynamicLoadTrusts;
import com.tremolosecurity.provisioning.mapping.MapIdentity;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.server.StopableThread;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;

public class K8sLoadTrusts implements DynamicLoadTrusts,StopableThread {
	
	static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(K8sLoadTrusts.class.getName());
	
	HashMap<String, OpenIDConnectTrust> trusts;

	private String k8sTarget;

	private String namespace;

	private String uri;

	private OpenShiftTarget k8s;
	
	private HashSet<String> resourceVersions;
	
	
	
	boolean keepRunning;
	
	@Override
	public void loadTrusts(String idpName, ServletContext ctx,
			HashMap<String, Attribute> init, HashMap<String, HashMap<String, Attribute>> trustCfg, MapIdentity mapper,HashMap<String, OpenIDConnectTrust> trusts)
			throws Exception {
		
		this.trusts = trusts;
		
		this.k8sTarget = 	init.get("trusts.k8starget").getValues().get(0);
		this.namespace = "openunison";//init.get("trusts.namespaces").getValues().get(0);
		this.uri = "/apis/openunison.tremolo.io/v1/namespaces/" + this.namespace + "/trusts";
		
		this.k8s = (OpenShiftTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(k8sTarget).getProvider();
		
		if (this.k8s == null) {
			throw new Exception("Target " + k8sTarget + " does not exist");
		}
		
		HttpCon http = this.k8s.createClient();
		
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
				addTrust(trusts, http, token, o);
				
				
			}
			
		} finally {
			http.getHttp().close();
			http.getBcm().close();
		}
		
		this.keepRunning = true;
		logger.info("Adding stoppable thread");
		GlobalEntries.getGlobalEntries().getConfigManager().addThread(this);
		logger.info("Starting watch");
		new Thread(this).start();
		
	}

	private void addTrust(HashMap<String, OpenIDConnectTrust> trusts, HttpCon http, String token, Object o)
			throws IOException, ClientProtocolException, ParseException {
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
		
		
		OpenIDConnectTrust trust = new OpenIDConnectTrust();
		trust.setClientID(spec.get("clientId").toString());
		trust.setPublicEndpoint((Boolean) spec.get("publicEndpoint"));
		
		if (! trust.isPublicEndpoint()) {
			JSONObject secretInfo = (JSONObject) spec.get("clientSecret");
			if (secretInfo == null) {
				logger.error("secretInfo not provided for trust " + metadata.get("name"));
				return;
			}
			String secretUri = "/api/v1/namespaces/" + namespace + "/secrets/" + secretInfo.get("secretName").toString();
			String secretJson = k8s.callWS(token, http, secretUri);
			JSONObject secret = (JSONObject) new JSONParser().parse(secretJson);
			
			JSONObject data = (JSONObject) secret.get("data");
			if (data == null) {
				logger.error("Invalid secret response for " + secretUri + " - " + secretJson);
				return;
			}
			
			
			
			String secretData = (String) data.get(secretInfo.get("keyName").toString());
			
			if (secretData == null) {
				logger.error("Secret key " + secretInfo.get("keyName").toString() + " does not exist");
				return;
			}
			
			
			
			String decoded = new String(java.util.Base64.getDecoder().decode(secretData));
			
			
			trust.setClientSecret(decoded);
		}
		
		
		
		trust.setRedirectURI(spec.get("redirectURI").toString());
		trust.setCodeLastmileKeyName(spec.get("codeLastMileKeyName").toString());
		trust.setAuthChain(spec.get("authChainName").toString());
		trust.setCodeTokenTimeToLive((Long) spec.get("codeTokenSkewMilis"));
		trust.setAccessTokenTimeToLive((Long) spec.get("accessTokenTimeToLive"));
		trust.setAccessTokenSkewMillis((Long) spec.get("accessTokenSkewMillis"));

		
		trust.setSignedUserInfo((Boolean) spec.get("signedUserInfo"));
		trust.setVerifyRedirect((Boolean) spec.get("verifyRedirect"));
		
		
		trust.setTrustName(metadata.get("name").toString());
		
		synchronized(trusts) {
			trusts.put(trust.getClientID(),trust);
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
						this.addTrust(trusts, nonwatchHttp, this.k8s.getAuthToken(), trust);
					} else {
						//deleted
						JSONObject metadata = (JSONObject) trust.get("metadata");
						String name = (String) metadata.get("name");
						logger.info("Deleting trust " + name);
						JSONObject spec = (JSONObject) trust.get("spec");
						String clientId = (String) spec.get("clientId");
						synchronized(trusts) {
							trusts.remove(clientId);
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

}
