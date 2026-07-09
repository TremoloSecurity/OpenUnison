/*******************************************************************************
 * Copyright 2023 Tremolo Security, Inc.
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

package com.tremolosecurity.provisioning.queue;

import java.io.IOException;
import java.util.HashMap;

import jakarta.jms.Message;

import org.apache.log4j.Logger;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.UnisonMessageListener;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;
import com.tremolosecurity.unison.openshiftv3.dr.DisasterRecoveryAction;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

public class DRSync extends UnisonMessageListener {
	String target;
	
	static Logger logger = Logger.getLogger(DRSync.class.getName());
	
	@Override
	public void onMessage(ConfigManager cfg, Object payload, Message msg) throws ProvisioningException {
		DisasterRecoveryAction drAction = (DisasterRecoveryAction) payload;

		logger.info("method :" + drAction.getMethod());
		logger.info("dr action : " + drAction.getUrl());
		
		if (logger.isDebugEnabled()) {
			logger.debug("full object : " + drAction.toString()) ;
		}
		
		
		OpenShiftTarget k8s = (OpenShiftTarget) cfg.getProvisioningEngine().getTarget(target).getProvider();
		
		HttpCon http = null;
		
		try {
			http = k8s.createClient();
			if (drAction.getMethod().equalsIgnoreCase("POST")) {
				String json = drAction.getJson();
				boolean replacedOwnerRef = false;
				if (k8s.getOwnerApiVersion() != null) {
					JSONObject root = (JSONObject) new JSONParser().parse(drAction.getJson());
					JSONObject metadata = (JSONObject) root.get("metadata");
					if (metadata != null) {

						JSONArray ownerReferences = (JSONArray) metadata.get("ownerReferences");
						if (ownerReferences != null) {
							String namespace = (String) metadata.get("namespace");
							for (Object o : ownerReferences) {
								JSONObject owner = (JSONObject) o;
								String ownerApiVersion = (String) owner.get("apiVersion");
								String ownerName = (String) owner.get("name");
								String ownerKind = (String) owner.get("kind");
								String uidFromK8s = k8s.getOwnerUid();
								if (ownerApiVersion != null && ownerApiVersion.equals(k8s.getOwnerApiVersion())
									&& ownerName != null && ownerName.equals(k8s.getOwnerName())
									&& ownerKind != null && ownerKind.equals(k8s.getOwnerKind())
									&& namespace != null && namespace.equals(k8s.getOwnerNamespace())
								) {
									replacedOwnerRef = true;
									owner.put("uid",uidFromK8s);
								}

							}

						}
					}

					if (replacedOwnerRef) {
						json = root.toString();
					}
				}



				logger.info(k8s.callWSPost(k8s.getAuthToken(), http, drAction.getUrl(), json));
			} else if (drAction.getMethod().equalsIgnoreCase("DELETE")) {
				logger.info(k8s.callWSDelete(k8s.getAuthToken(), http, drAction.getUrl()));
			} else if (drAction.getMethod().equalsIgnoreCase("PATCH")) {
				logger.info(k8s.callWSPatchJson(k8s.getAuthToken(), http, drAction.getUrl(), drAction.getJson(), drAction.getContentType()));
			} else if (drAction.getMethod().equalsIgnoreCase("PUT")) {

				JSONObject jsonToPut = (JSONObject) new JSONParser().parse(drAction.getJson());
				JSONObject metadata = (JSONObject) jsonToPut.get("metadata");
				if (metadata != null) {
					String resourceVersion = (String) metadata.get("resourceVersion");
					if (resourceVersion != null) {
						// There's a resource version, must be removed
						metadata.remove("resourceVersion");

					}
				}

				// now add the latest resourceVersion

				String jsonFromAPI = k8s.callWS(k8s.getAuthToken(), http, drAction.getUrl());
				JSONObject fromApi = (JSONObject) new JSONParser().parse(jsonFromAPI);
				JSONObject fromApiMetadata = (JSONObject) fromApi.get("metadata");
				if (fromApiMetadata != null) {
					String resourceVersion = (String) fromApiMetadata.get("resourceVersion");
					if (resourceVersion != null) {
						metadata.put("resourceVersion", resourceVersion);
					}
				}


				boolean replacedOwnerRef = false;
				if (k8s.getOwnerApiVersion() != null) {
					JSONObject root = jsonToPut;

					if (metadata != null) {

						JSONArray ownerReferences = (JSONArray) metadata.get("ownerReferences");
						if (ownerReferences != null) {
							String namespace = (String) metadata.get("namespace");
							for (Object o : ownerReferences) {
								JSONObject owner = (JSONObject) o;
								String ownerApiVersion = (String) owner.get("apiVersion");
								String ownerName = (String) owner.get("name");
								String ownerKind = (String) owner.get("kind");
								String uidFromK8s = k8s.getOwnerUid();
								if (ownerApiVersion != null && ownerApiVersion.equals(k8s.getOwnerApiVersion())
										&& ownerName != null && ownerName.equals(k8s.getOwnerName())
										&& ownerKind != null && ownerKind.equals(k8s.getOwnerKind())
										&& namespace != null && namespace.equals(k8s.getOwnerNamespace())
								) {
									replacedOwnerRef = true;
									owner.put("uid",uidFromK8s);
								}

							}

						}
					}


				}

				drAction.setJson(jsonToPut.toString());

				logger.info(k8s.callWSPut(k8s.getAuthToken(), http, drAction.getUrl(),drAction.getJson()));
			}
		} catch (Exception e) {
			throw new ProvisioningException("Could not sync dr action",e);
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

	@Override
	public void init(ConfigManager cfg, HashMap<String, Attribute> attributes) throws ProvisioningException {
		this.target = attributes.get("target").getValues().get(0);

	}

}
