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

import javax.jms.Message;

import org.apache.log4j.Logger;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.UnisonMessageListener;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;
import com.tremolosecurity.unison.openshiftv3.dr.DisasterRecoveryAction;

public class DRSync extends UnisonMessageListener {
	String target;
	
	static Logger logger = Logger.getLogger(DRSync.class.getName());
	
	@Override
	public void onMessage(ConfigManager cfg, Object payload, Message msg) throws ProvisioningException {
		DisasterRecoveryAction drAction = (DisasterRecoveryAction) payload;
		
		logger.info("dr action : " + drAction.toString());
		
		
		OpenShiftTarget k8s = (OpenShiftTarget) cfg.getProvisioningEngine().getTarget(target).getProvider();
		
		HttpCon http = null;
		
		try {
			http = k8s.createClient();
			if (drAction.getMethod().equalsIgnoreCase("POST")) {
				logger.info(k8s.callWSPost(k8s.getAuthToken(), http, drAction.getUrl(), drAction.getJson()));
			} else if (drAction.getMethod().equalsIgnoreCase("DELETE")) {
				logger.info(k8s.callWSDelete(k8s.getAuthToken(), http, drAction.getUrl()));
			} else if (drAction.getMethod().equalsIgnoreCase("PATCH")) {
				logger.info(k8s.callWSPatchJson(k8s.getAuthToken(), http, drAction.getUrl(), drAction.getJson(), drAction.getContentType()));
			} else if (drAction.getMethod().equalsIgnoreCase("PUT")) {
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
