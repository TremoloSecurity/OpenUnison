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
package com.tremolosecurity.provisioning.portal;

import java.util.Map;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.TremoloType;
import com.tremolosecurity.provisioning.core.ProvisioningEngine;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.saml.Attribute;

public interface DynamicPortalUrls {
	
	public void loadDynamicPortalUrls(ConfigManager cfgMgr,ProvisioningEngine provisioningEngine,Map<String,Attribute> configAttributes) throws ProvisioningException;

}