/*******************************************************************************
 * Copyright 2020 Tremolo Security, Inc.
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
package com.tremolosecurity.argocd.targets;

import java.util.ArrayList;
import java.util.Map;
import java.util.Set;

import org.apache.http.Header;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.message.BasicHeader;

import com.google.gson.Gson;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.UserStoreProvider;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;

public class ArgoCDTarget implements UserStoreProvider {

	String name;
	String url;
	String token;
	
	
	
	
	@Override
	public void createUser(User user, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		throw new ProvisioningException("Unsuported");

	}

	@Override
	public void setUserPassword(User user, Map<String, Object> request) throws ProvisioningException {
		throw new ProvisioningException("Unsuported");

	}

	@Override
	public void syncUser(User user, boolean addOnly, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		throw new ProvisioningException("Unsuported");

	}

	@Override
	public void deleteUser(User user, Map<String, Object> request) throws ProvisioningException {
		throw new ProvisioningException("Unsuported");

	}

	@Override
	public User findUser(String userID, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		throw new ProvisioningException("Unsuported");
	}

	@Override
	public void init(Map<String, Attribute> cfg, ConfigManager cfgMgr, String name) throws ProvisioningException {
		this.name = name;
		this.url = cfg.get("url").getValues().get(0);
		
		this.token = cfg.get("token").getValues().get(0);;
		
		

	}

	public HttpCon createConnection() {
		ArrayList<Header> defheaders = new ArrayList<Header>();
		
		defheaders.add(new BasicHeader("Authorization", new StringBuilder().append("Bearer ").append(this.token).toString()));

		BasicHttpClientConnectionManager bhcm = new BasicHttpClientConnectionManager(
				GlobalEntries.getGlobalEntries().getConfigManager().getHttpClientSocketRegistry());

		RequestConfig rc = RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD).setRedirectsEnabled(false)
				.build();

		CloseableHttpClient http = HttpClients.custom()
				                  .setConnectionManager(bhcm)
				                  .setDefaultHeaders(defheaders)
				                  .setDefaultRequestConfig(rc)
				                  .build();
		return new HttpCon(http,bhcm);
	}

	public String getUrl() {
		return this.url;
	}

	public String getName() {
		return this.name;
	}
}
