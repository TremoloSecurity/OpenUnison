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
package com.tremolosecurity.scalejs.register.sdk.test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.service.util.WFCall;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.scalejs.register.cfg.ScaleJSRegisterConfig;
import com.tremolosecurity.scalejs.register.data.NewUserRequest;
import com.tremolosecurity.scalejs.register.sdk.CreateRegisterUser;
import com.tremolosecurity.scalejs.register.ws.ScaleRegister;

public class TestRegisterUser implements CreateRegisterUser {
	
	static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(TestRegisterUser.class.getName());

	@Override
	public void init(ScaleJSRegisterConfig registerConfig)
			throws ProvisioningException {
		logger.info("config:" + registerConfig.getCustomSubmissionConfig().get("option1"));

	}

	@Override
	public String createTremoloUser(NewUserRequest newUser, List<String> errors,AuthInfo userData) throws ProvisioningException {
		errors.add("This doesn't do anything");
		return null;
	}

	@Override
	public void setWorkflowParameters(Map<String, Object> wfParameters, NewUserRequest newUser, AuthInfo userData)
			throws ProvisioningException {
		// TODO Auto-generated method stub
		
	}

}
