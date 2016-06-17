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
package com.tremolosecurity.unison.openshiftv3;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.net.util.Base64;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.apache.logging.log4j.Logger;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.UserStoreProvider;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.unison.openshiftv3.model.groups.GroupItem;

public class OpenShiftTarget implements UserStoreProvider {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(OpenShiftTarget.class.getName());

	String url;
	String userName;
	String password;

	private ConfigManager cfgMgr;

	private String name;

	@Override
	public void createUser(User user, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		// TODO Auto-generated method stub

	}

	@Override
	public void setUserPassword(User user, Map<String, Object> request) throws ProvisioningException {
		// TODO Auto-generated method stub

	}

	@Override
	public void syncUser(User user, boolean addOnly, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		// TODO Auto-generated method stub

	}

	@Override
	public void deleteUser(User user, Map<String, Object> request) throws ProvisioningException {
		// TODO Auto-generated method stub

	}

	@Override
	public User findUser(String userID, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		try {
			User user = null;
			String token = this.getAuthToken();
			
			//users aren't bound to groups and there's no way to directly lookup what groups a user has
			//so we need to read all groups and see if the user exists
			
			ArrayList<String> groupsForUser = new ArrayList<String>();
			HttpCon con = this.createClient();
			StringBuffer b = new StringBuffer();
			
			com.tremolosecurity.unison.openshiftv3.model.List<GroupItem> groupList = null;
			
			try {
				
				String json = callWS(token, con,"/oapi/v1/groups");
				Gson gson = new Gson();
				TypeToken<com.tremolosecurity.unison.openshiftv3.model.List<GroupItem>> tokenType = new TypeToken<com.tremolosecurity.unison.openshiftv3.model.List<GroupItem>>() {};
				groupList = gson.fromJson(json, tokenType.getType());
				
				b.append("/oapi/v1/users/").append(userID);
				json = callWS(token,con,b.toString());
				
				
				com.tremolosecurity.unison.openshiftv3.model.users.User osUser = gson.fromJson(json, com.tremolosecurity.unison.openshiftv3.model.users.User.class);
				
				if (osUser.getKind().equalsIgnoreCase("User")) {
				
					user = new User(userID);
					
					for (String attrName : osUser.getMetadata().keySet()) {
						if (attributes.contains(attrName)) {
							user.getAttribs().put(attrName, new Attribute(attrName,osUser.getMetadata().get(attrName)));
						}
					}
				}
				
			} finally {
				if (con != null) {
					con.getBcm().shutdown();
				}
			}
			
			for (GroupItem group : groupList.getItems()) {
				if (group.getUsers().contains(userID)) {
					groupsForUser.add(group.getMetadata().get("name"));
				}
			}
			
			if (groupsForUser.isEmpty()) {
				return user;
			} else {
				if (user == null) {
					user = new User(userID);
				}
				user.getGroups().addAll(groupsForUser);
				return user;
			}
		} catch (Exception e) {
			throw new ProvisioningException("Could not load " + userID,e);
		}
	}

	private String callWS(String token, HttpCon con,String uri) throws IOException, ClientProtocolException {
		StringBuffer b = new StringBuffer();
		
		b.append(this.url).append(uri);
		HttpGet get = new HttpGet(b.toString());
		b.setLength(0);
		b.append("Bearer ").append(token);
		get.addHeader(new BasicHeader("Authorization","Bearer " + token));
		HttpResponse resp = con.getHttp().execute(get);
		
		String json = EntityUtils.toString(resp.getEntity());
		return json;
	}

	@Override
	public void init(Map<String, Attribute> cfg, ConfigManager cfgMgr, String name) throws ProvisioningException {
		this.url = this.loadOption("url", cfg, false);
		this.userName = this.loadOption("userName", cfg, false);
		this.password = this.loadOption("password", cfg, true);

		this.cfgMgr = cfgMgr;
		this.name = name;

	}

	private String loadOption(String name, Map<String, Attribute> cfg, boolean mask) throws ProvisioningException {
		if (!cfg.containsKey(name)) {
			throw new ProvisioningException(name + " is required");
		} else {
			String val = cfg.get(name).getValues().get(0);
			if (!mask) {
				logger.info("Config " + name + "='" + val + "'");
			} else {
				logger.info("Config " + name + "='*****'");
			}

			return val;
		}
	}

	

	private HttpCon createClient() throws Exception {
		ArrayList<Header> defheaders = new ArrayList<Header>();
		defheaders.add(new BasicHeader("X-Csrf-Token", "1"));

		BasicHttpClientConnectionManager bhcm = new BasicHttpClientConnectionManager(
				cfgMgr.getHttpClientSocketRegistry());

		RequestConfig rc = RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD).setRedirectsEnabled(false)
				.build();

		CloseableHttpClient http = HttpClients.custom()
				                  .setConnectionManager(bhcm)
				                  .setDefaultHeaders(defheaders)
				                  .setDefaultRequestConfig(rc)
				                  .build();

		HttpCon con = new HttpCon();
		con.setBcm(bhcm);
		con.setHttp(http);

		return con;

	}

	private String getAuthToken() throws Exception {
		HttpCon con = this.createClient();
		try {
			StringBuffer b = new StringBuffer();
			b.append(this.url).append("/oauth/authorize?client_id=openshift-challenging-client&response_type=token");
			HttpGet get = new HttpGet(b.toString());
			b.setLength(0);
			b.append(this.userName).append(':').append(this.password);
			String b64 = Base64.encodeBase64String(b.toString().getBytes("UTF-8"));
			b.setLength(0);
			b.append("Basic ").append(b64.substring(0, b64.length() - 1));
			get.addHeader(new BasicHeader("Authorization",b.toString()));
			
			HttpResponse resp = con.getHttp().execute(get);
			String token = "";
			if (resp.getStatusLine().getStatusCode() == 302) {
				String url = resp.getFirstHeader("Location").getValue();
				int start = url.indexOf("access_token") + "access_token=".length();
				int end = url.indexOf("&",start + 1);
				token = url.substring(start, end);
				
			} else {
				throw new Exception("Unable to obtain token : " + resp.getStatusLine().toString());
			}
			
			
			
			return token;
		} finally {
			if (con != null) {
				con.getBcm().shutdown();
			}
		}
	}

}
