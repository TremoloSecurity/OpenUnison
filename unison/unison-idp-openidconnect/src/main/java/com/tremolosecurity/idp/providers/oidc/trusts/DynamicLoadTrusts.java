/*******************************************************************************
 * Copyright 2020 Tremolo Security, Inc.
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

package com.tremolosecurity.idp.providers.oidc.trusts;

import java.util.HashMap;

import jakarta.servlet.ServletContext;

import com.tremolosecurity.idp.providers.OpenIDConnectTrust;
import com.tremolosecurity.provisioning.mapping.MapIdentity;
import com.tremolosecurity.saml.Attribute;

public interface DynamicLoadTrusts {

	public void loadTrusts(String idpName,ServletContext ctx, HashMap<String, Attribute> init, HashMap<String, HashMap<String, Attribute>> trustCfg,MapIdentity mapper,HashMap<String,OpenIDConnectTrust> trusts) throws Exception;
	
}
