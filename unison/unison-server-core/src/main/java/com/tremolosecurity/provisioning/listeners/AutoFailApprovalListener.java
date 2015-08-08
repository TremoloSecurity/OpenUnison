/*******************************************************************************
 * Copyright 2015 Tremolo Security, Inc.
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
package com.tremolosecurity.provisioning.listeners;

import java.util.HashMap;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.jms.Message;

import com.google.gson.Gson;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.json.Token;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.UnisonMessageListener;
import com.tremolosecurity.provisioning.scheduler.jobs.util.FailApproval;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;

public class AutoFailApprovalListener extends UnisonMessageListener {

	@Override
	public void onMessage(ConfigManager cfg, Object payload, Message msg)
			throws ProvisioningException {
		FailApproval fa = (FailApproval) payload;
		GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().doApproval(fa.getApprovalID(), fa.getApprover(), false, fa.getMsg());

	}

	@Override
	public void init(ConfigManager cfg, HashMap<String, Attribute> attributes)
			throws ProvisioningException {
		

	}

}
