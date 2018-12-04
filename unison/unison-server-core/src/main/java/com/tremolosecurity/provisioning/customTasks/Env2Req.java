/*******************************************************************************
 * Copyright 2018 Tremolo Security, Inc.
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
package com.tremolosecurity.provisioning.customTasks;

import java.util.HashMap;
import java.util.Map;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;

/**
 * Env2Req
 */
public class Env2Req implements CustomTask {

    HashMap<String,String> mapping;

	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
		this.mapping = new HashMap<String,String>();
		for (String key : params.keySet()) {
            mapping.put(key, params.get(key).getValues().get(0));
        }
	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
		
	}

	@Override
	public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {
        for (String key : this.mapping.keySet()) {
            request.put(key, System.getenv(this.mapping.get(key)));
        }
		return true;
	}

    
}