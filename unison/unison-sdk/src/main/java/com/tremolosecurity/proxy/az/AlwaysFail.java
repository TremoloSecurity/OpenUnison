/*******************************************************************************
 * Copyright 2021 Tremolo Security, Inc.
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
package com.tremolosecurity.proxy.az;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.saml.Attribute;

public class AlwaysFail implements CustomAuthorization {

	@Override
	public void init(Map<String, Attribute> config) throws AzException {
		

	}

	@Override
	public void loadConfigManager(ConfigManager cfg) throws AzException {
		

	}

	@Override
	public void setWorkflow(Workflow wf) throws AzException {
		

	}

	@Override
	public boolean isAuthorized(AuthInfo subject, String... params) throws AzException {
		
		return false;
	}

	@Override
	public List<String> listPossibleApprovers(String... params) throws AzException {
		return new ArrayList<String>();
	}

	@Override
	public Workflow getWorkflow() {
		return null;
	}

}
