/*******************************************************************************
 * Copyright 2016 Tremolo Security, Inc.
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
package com.tremolosecurity.provisioning.util;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.WorkflowType;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.saml.Attribute;

public interface DynamicWorkflow {

	
	
	
	
	/**
	 * Generates a list of name/value pairs to be inserted into the request
	 * @param wf
	 * @param cfg
	 * @param params
	 * @return
	 * @throws ProvisioningException
	 */
	public List<Map<String,String>> generateWorkflows(WorkflowType wf,ConfigManager cfg,HashMap<String,Attribute> params) throws ProvisioningException;
	
	/**
	 * Generates a list of name/value pairs to be inserted into the request, includes the current user's info
	 * @param wf
	 * @param cfg
	 * @param params
	 * @param authInfo
	 * @return
	 * @throws ProvisioningException
	 */
	public List<Map<String,String>> generateWorkflows(WorkflowType wf,ConfigManager cfg,HashMap<String,Attribute> params,AuthInfo authInfo) throws ProvisioningException;
	
}
