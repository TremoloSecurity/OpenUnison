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
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.util.NVP;

public interface CustomAuthorization {
	
	/**
	 * Initializes the custom AZ rule with a the name of the attribute that identifies the subject and a list of name/value pairs.  This method will
	 * be called for stateless authorizations (ie authorizations to a site or resource)
	 * @param subjectAttributeName The name of the attribute that identifies the subject
	 * @param config Name/Value pairs
	 * @throws AzException
	 */
	public abstract void init(String subjectAttributeName,Map<String,Attribute> config) throws AzException;
	
	/**
	 * Initializes the custom AZ rule with the name of the attribute that identifies the subect, a list of name/value pairs and an attribute that identifies the subject
	 * that this rule is relative to.  This method will be called for stateful authorizations such as in workflows
	 * @param subjectAttributeName Name of the attribute that identifies the subject
	 * @param subjectAttributeValue Identifier for the subject this rule is relative to
	 * @param config Name/Value pairs
	 * @throws AzException
	 */
	public abstract void init(String subjectAttributeName, String subjectAttributeValue,Map<String,Attribute> config) throws AzException;
	
	/**
	 * Sets the config manager for access to Unison resources, run on each de-serialization
	 * @param cfg
	 * @throws AzException
	 */
	public abstract void loadConfigManager(ConfigManager cfg) throws AzException;
	
	/**
	 * Determines if the subject in the parameter is authorized by this rule
	 * @param subject Subject to be tested
	 * @return True if authorized, False if not
	 * @throws AzException
	 */
	public abstract boolean isAuthorized(AuthInfo subject) throws AzException;
	
	/**
	 * Provides a list of subjects that could be authorized based on this rule.  The value of each list item should be
	 * the value of the attribute named by subjectAttributeName for each user
	 * @return
	 */
	public abstract List<String> listPossibleApprovers();
	
}
