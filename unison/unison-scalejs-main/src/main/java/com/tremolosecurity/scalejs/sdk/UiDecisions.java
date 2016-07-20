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
package com.tremolosecurity.scalejs.sdk;

import java.util.HashMap;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.saml.Attribute;

public interface UiDecisions {
	/**
	 * Initializes the decision class
	 * @param config
	 */
	public void init(HashMap<String,Attribute> config);
	
	/**
	 * Returns true if the currently logged in user can be edited
	 * @return
	 */
	public boolean canEditUser(AuthInfo user, HttpServletRequest request);
	
	/**
	 * Return a subset of attributes that a user is able to edit.  Return null if all attributes are available
	 * @param user
	 * @param request
	 * @return
	 */
	public Set<String> availableAttributes(AuthInfo user,HttpServletRequest request);
	
}
