/*******************************************************************************
 * Copyright 2018 Tremolo Security, Inc.
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
package com.tremolosecurity.idp.providers.oidc.model;

import java.util.HashMap;
import java.util.List;

import jakarta.servlet.ServletContext;

import org.joda.time.DateTime;

import com.tremolosecurity.provisioning.mapping.MapIdentity;
import com.tremolosecurity.saml.Attribute;

public interface OidcSessionStore {
	
	public void init(String idpName,ServletContext ctx, HashMap<String, Attribute> init,
			HashMap<String, HashMap<String, Attribute>> trustCfg,MapIdentity mapper) throws Exception;
	
	public void saveUserSession(OidcSessionState session) throws Exception;
	
	public void deleteSession(String sessionId) throws Exception;
	
	public void deleteAllSessions(String sessionId) throws Exception;
	
	public OidcSessionState getSession(String sessionId) throws Exception;
	
	public void resetSession(OidcSessionState session) throws Exception;
	
	public void cleanOldSessions() throws Exception; 
	
	public void shutdown() throws Exception;

}
