/*******************************************************************************
 * Copyright 2015, 2016 Tremolo Security, Inc.
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
package com.tremolosecurity.unison.proxy.auth.openidconnect.loadUser;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.unison.proxy.auth.openidconnect.sdk.LoadUserData;

public class NoUserToken implements LoadUserData {

	public Map loadUserAttributesFromIdP(HttpServletRequest request, HttpServletResponse response, ConfigManager cfg,
			HashMap<String, Attribute> authParams, Map accessToken) throws Exception {
		Map jwtNVP = new HashMap<String,String>();
		String uidAttr = authParams.get("uidAttr").getValues().get(0);
		jwtNVP.put(uidAttr, UUID.randomUUID().toString());
		return jwtNVP;
	}

}
