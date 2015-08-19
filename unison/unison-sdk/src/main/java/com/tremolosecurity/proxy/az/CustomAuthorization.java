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
package com.tremolosecurity.proxy.az;

import java.util.List;
import java.util.Map;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.util.NVP;

public interface CustomAuthorization {
	
	/**
	 * Initializes the custom AZ rule with the configuration
	 * @param config Name/Value pairs
	 * @throws AzException
	 */
	public abstract void init(Map<String,Attribute> config) throws AzException;
	
	
	/**
	 * Sets the config manager for access to Unison resources, run on each de-serialization
	 * @param cfg
	 * @throws AzException
	 */
	public abstract void loadConfigManager(ConfigManager cfg) throws AzException;
	
	
	/**
	 * Sets the workflow this rule will be a part of.  Called after cloning an instance of the rule for a particular workflow
	 * @param wf
	 * @throws AzException
	 */
	public abstract void setWorkflow(Workflow wf) throws AzException;
	
	
	
	
	
	/**
	 * Determines if the subject in the parameter is authorized by this rule
	 * @param subject Subject to be tested
	 * @return True if authorized, False if not
	 * @throws AzException
	 */
	public abstract boolean isAuthorized(AuthInfo subject) throws AzException;
	
	/**
	 * Provides a list of subjects that could be authorized based on this rule.  The value of each list item should be
	 * the distinguished name of the user in Unison
	 * @return
	 */
	public abstract List<String> listPossibleApprovers() throws AzException;
	
}
