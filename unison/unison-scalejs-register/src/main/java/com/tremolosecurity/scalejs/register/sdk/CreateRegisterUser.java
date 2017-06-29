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
package com.tremolosecurity.scalejs.register.sdk;

import java.util.HashMap;
import java.util.List;

import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.scalejs.register.cfg.ScaleJSRegisterConfig;
import com.tremolosecurity.scalejs.register.data.NewUserRequest;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.service.util.WFCall;
import com.tremolosecurity.proxy.auth.AuthInfo;

public interface CreateRegisterUser {
	/**
	 * Initializes the custom submission generator
	 * @param registerConfig
	 * @throws ProvisioningException
	 */
	public void init(ScaleJSRegisterConfig registerConfig) throws ProvisioningException;
	
	/**
	 * Returns the name of the workflow to execute, any changes to newUser are reflected in the request
	 * @param newUser
	 * @param errors
	 * @param userData 
	 * @return
	 * @throws ProvisioningException
	 */
	public String createTremoloUser(NewUserRequest newUser,List<String> errors, AuthInfo userData) throws ProvisioningException;
}
