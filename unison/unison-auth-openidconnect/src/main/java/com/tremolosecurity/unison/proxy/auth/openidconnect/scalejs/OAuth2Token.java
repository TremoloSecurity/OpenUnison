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
package com.tremolosecurity.unison.proxy.auth.openidconnect.scalejs;

import java.util.HashMap;

import javax.servlet.http.HttpSession;

import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.scalejs.token.cfg.ScaleTokenConfig;
import com.tremolosecurity.scalejs.token.sdk.TokenLoader;

public class OAuth2Token implements TokenLoader {

	String sessionAttributeName;
	
	public void init(HttpFilterConfig config, ScaleTokenConfig scaleTokenConfig) throws Exception {
		this.sessionAttributeName = config.getAttribute("oauth2AccessTokenAttributeName").getValues().get(0);

	}

	public Object loadToken(AuthInfo user, HttpSession session) throws Exception {
		String token = (String) session.getAttribute(this.sessionAttributeName);
		
		HashMap<String,String> tokens = new HashMap<String,String>();
		
		
		if (token == null) {
			tokens.put("OAuth 2 Bearer Token", "No token found");
		} else {
			tokens.put("OAuth 2 Bearer Token", token);
		}
		
		return tokens;
	}

}
