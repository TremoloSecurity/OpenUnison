/*******************************************************************************
 * Copyright 2016 Tremolo Security, Inc.
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
package com.tremolosecurity.scalejs.token.sdk;

import java.net.http.HttpRequest;
import java.util.HashMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.scalejs.token.cfg.ScaleTokenConfig;

public interface TokenLoader {

	/**
	 * Called when the insert is loaded with configuration parameters
	 * @param params
	 * @throws Exception
	 */
	public void init(HttpFilterConfig config,ScaleTokenConfig scaleTokenConfig) throws Exception;
	
	
	/**
	 * Return an object to be serialized to JSON and sent to the client
	 * @param user The logged in user
	 * @param session The user's session
	 * @param request The user's request
	 * @return Object to serialize
	 * @throws Exception
	 */
	public Object loadToken(AuthInfo user,HttpSession session,HttpServletRequest request) throws Exception;
	
}
