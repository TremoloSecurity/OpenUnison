/*******************************************************************************
 * Copyright (c) 2022 Tremolo Security, Inc.
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
package com.tremolosecurity.openunison.notifications;

import java.util.Map;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningEngine;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.saml.Attribute;

/**
 * Interface for loading notifiers dynamically
 * @author marcboorshtein
 *
 */
public interface DynamicNotifiers {
	/**
	 * Sets up a dynamic listener for changes to notifiers
	 * @param cfgMgr
	 * @param provisioningEngine
	 * @param configAttributes
	 * @throws ProvisioningException
	 */
	public void loadDynamicNotifiers(ConfigManager cfgMgr,ProvisioningEngine provisioningEngine,Map<String,Attribute> configAttributes) throws ProvisioningException;
}
