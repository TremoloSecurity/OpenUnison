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
package com.tremolosecurity.scalejs;

import java.net.URLEncoder;
import java.util.HashMap;

import javax.servlet.http.HttpSession;

import org.apache.logging.log4j.Logger;
import org.joda.time.DateTime;

import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.auth.GenerateOIDCTokens;
import com.tremolosecurity.proxy.auth.util.OpenIDConnectToken;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.scalejs.token.cfg.ScaleTokenConfig;
import com.tremolosecurity.scalejs.token.sdk.TokenLoader;

public class IdTokenLoader implements TokenLoader {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(IdTokenLoader.class);
	
	String idTokenURL;
	
	boolean showTokenURL;
	boolean showClientSecret;
	String usage;
	
	
	@Override
	public void init(HttpFilterConfig config, ScaleTokenConfig scaleTokenConfig) throws Exception {
		this.idTokenURL = config.getAttribute("idTokenURL").getValues().get(0);
		this.showTokenURL = config.getAttribute("showTokenURL").getValues().get(0).equalsIgnoreCase("true");
		this.showClientSecret = config.getAttribute("showClientSecret").getValues().get(0).equalsIgnoreCase("true");
		this.usage = config.getAttribute("usage").getValues().get(0);
	}

	@Override
	public Object loadToken(AuthInfo user, HttpSession session) throws Exception {
		OpenIDConnectToken token = (OpenIDConnectToken) session.getAttribute(GenerateOIDCTokens.UNISON_SESSION_OIDC_ID_TOKEN);
		if (token == null) {
			logger.warn("No id token found");
			return new HashMap<String,String>();
		} else {
			
			synchronized (token) {
				
				token.loadFromDB(session);
				
				if (token.isExpired()) {
					token.generateToken(session);
				}
			}
			
			HashMap<String,String> tokens = new HashMap<String,String>();
			tokens.put("Expires", new DateTime(token.getExpires()).toString());
			tokens.put("ID Token", token.getEncodedIdJSON());
			tokens.put("Access Token", token.getAccessEncodedJSON());
			tokens.put("Refresh Token", token.getRefreshToken());
			
			if (this.showClientSecret) {
				tokens.put("Client Secret for Session", token.getDecryptedClientSecret());
			}
			
			if (this.showTokenURL) {
				StringBuffer b = new StringBuffer();
				b.append(this.idTokenURL).append("?refresh_token=").append(URLEncoder.encode(token.getRefreshToken(),"UTF-8"));
				tokens.put("ID Token URL", b.toString());
			}
			tokens.put("Usage", usage);
			
			return tokens;
		}
		
	}

}
