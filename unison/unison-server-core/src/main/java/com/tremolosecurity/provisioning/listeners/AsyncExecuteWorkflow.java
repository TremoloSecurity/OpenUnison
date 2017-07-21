/*******************************************************************************
 * Copyright 2015, 2017 Tremolo Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/

package com.tremolosecurity.provisioning.listeners;

import java.util.HashMap;

import javax.jms.Message;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.UnisonMessageListener;
import com.tremolosecurity.provisioning.service.util.WFCall;
import com.tremolosecurity.saml.Attribute;

public class AsyncExecuteWorkflow extends UnisonMessageListener {

	@Override
	public void onMessage(ConfigManager cfg, Object payload, Message msg) throws ProvisioningException {
		WFCall call = (WFCall) payload;
		cfg.getProvisioningEngine().getWorkFlow(call.getName()).executeWorkflow(call);

	}

	@Override
	public void init(ConfigManager cfg, HashMap<String, Attribute> attributes) throws ProvisioningException {
		// TODO Auto-generated method stub

	}

}
