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

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.proxy.auth.openidconnect.sdk.LoadUserData;

public class LoadAttributesFromWS implements LoadUserData {

	public Map loadUserAttributesFromIdP(HttpServletRequest request, HttpServletResponse response, ConfigManager cfg,
			HashMap<String, Attribute> authParams, Map accessToken) throws Exception {
		String bearerTokenName = authParams.get("bearerTokenName").getValues().get(0);
		String url = authParams.get("restURL").getValues().get(0);
		
		BasicHttpClientConnectionManager bhcm = new BasicHttpClientConnectionManager(GlobalEntries.getGlobalEntries().getConfigManager().getHttpClientSocketRegistry());
		RequestConfig rc = RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD).build();
		CloseableHttpClient http = HttpClients.custom().setConnectionManager(bhcm).setDefaultRequestConfig(rc).build();
		    
		HttpGet get = new HttpGet(url);
		String header = new StringBuilder().append("Bearer ").append(request.getSession().getAttribute(bearerTokenName)).toString();
		get.addHeader("Authorization", header);
		
		CloseableHttpResponse httpResp = http.execute(get);
		
		if (httpResp.getStatusLine().getStatusCode() != 200) {				
			throw new Exception("Could not retrieve token : " + httpResp.getStatusLine().getStatusCode() + " / " + httpResp.getStatusLine().getReasonPhrase());				
		}
		
		
		BufferedReader in = new BufferedReader(new InputStreamReader(httpResp.getEntity().getContent()));
		
		StringBuffer token = new StringBuffer();
		
		
		String line = null;
		while ((line = in.readLine()) != null) {
			token.append(line);
		}
		
		
		
		httpResp.close();
		bhcm.close();
		
		Map jwtNVP = com.cedarsoftware.util.io.JsonReader.jsonToMaps(token.toString());
		
		return jwtNVP;
		
	}

}
