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

import java.util.HashMap;

import javax.servlet.ServletContext;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import com.tremolosecurity.idp.providers.OpenIDConnectIdP;
import com.tremolosecurity.idp.providers.OpenIDConnectTrust;
import com.tremolosecurity.idp.providers.oidc.trusts.DynamicLoadTrusts;
import com.tremolosecurity.provisioning.mapping.MapIdentity;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;

public class K8sLoadTrusts implements DynamicLoadTrusts {
	
	static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(K8sLoadTrusts.class.getName());
	
	
	@Override
	public void loadTrusts(String idpName, ServletContext ctx,
			HashMap<String, Attribute> init, HashMap<String, HashMap<String, Attribute>> trustCfg, MapIdentity mapper,HashMap<String, OpenIDConnectTrust> trusts)
			throws Exception {
		

		
		String k8sTarget = 	init.get("trusts.k8starget").getValues().get(0);
		String namespace = "openunison";//init.get("trusts.namespaces").getValues().get(0);
		String uri = "/apis/openunison.tremolo.io/v1/namespaces/" + namespace + "/trusts";
		
		OpenShiftTarget k8s = (OpenShiftTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(k8sTarget).getProvider();
		
		if (k8s == null) {
			throw new Exception("Target " + k8sTarget + " does not exist");
		}
		
		HttpCon http = k8s.createClient();
		
		try {
			String token = k8s.getAuthToken();
			String json = k8s.callWS(token, http, uri);
			System.out.println(json);
			
			JSONObject list = (JSONObject) new JSONParser().parse(json);
			JSONArray items = (JSONArray) list.get("items");
			
			if (items == null) {
				logger.error("Invalid JSON Response : '" + json + "'");
				return;
			}
			
			for (Object o : items) {
				JSONObject trustObj = (JSONObject) o;
				JSONObject metadata = (JSONObject) trustObj.get("metadata");
				JSONObject spec = (JSONObject) trustObj.get("spec");
				logger.info(metadata.get("name"));
				
				
				OpenIDConnectTrust trust = new OpenIDConnectTrust();
				trust.setClientID(spec.get("clientId").toString());
				trust.setPublicEndpoint((Boolean) spec.get("publicEndpoint"));
				
				if (! trust.isPublicEndpoint()) {
					JSONObject secretInfo = (JSONObject) spec.get("clientSecret");
					if (secretInfo == null) {
						logger.error("secretInfo not provided for trust " + metadata.get("name"));
						continue;
					}
					String secretUri = "/api/v1/namespaces/" + namespace + "/secrets/" + secretInfo.get("secretName").toString();
					String secretJson = k8s.callWS(token, http, secretUri);
					JSONObject secret = (JSONObject) new JSONParser().parse(secretJson);
					
					JSONObject data = (JSONObject) secret.get("data");
					if (data == null) {
						logger.error("Invalid secret response for " + secretUri + " - " + secretJson);
						continue;
					}
					
					
					
					String secretData = (String) data.get(secretInfo.get("keyName").toString());
					
					if (secretData == null) {
						logger.error("Secret key " + secretInfo.get("keyName").toString() + " does not exist");
						continue;
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
				
				trusts.put(trust.getClientID(),trust);
				
				
			}
			
		} finally {
			http.getHttp().close();
			http.getBcm().close();
		}
		
		
		
	}

}
