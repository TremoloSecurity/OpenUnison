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
package com.tremolosecurity.unison.openstack;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.apache.logging.log4j.Logger;


import com.google.gson.Gson;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.UserStoreProvider;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.unison.openstack.model.GroupLookupResponse;
import com.tremolosecurity.unison.openstack.model.GroupResponse;
import com.tremolosecurity.unison.openstack.model.KSDomain;
import com.tremolosecurity.unison.openstack.model.KSGroup;
import com.tremolosecurity.unison.openstack.model.KSRoleAssignment;
import com.tremolosecurity.unison.openstack.model.KSUser;
import com.tremolosecurity.unison.openstack.model.Role;
import com.tremolosecurity.unison.openstack.model.RoleAssignmentResponse;
import com.tremolosecurity.unison.openstack.model.TokenRequest;
import com.tremolosecurity.unison.openstack.model.TokenResponse;
import com.tremolosecurity.unison.openstack.model.UserHolder;
import com.tremolosecurity.unison.openstack.model.UserLookupResponse;
import com.tremolosecurity.unison.openstack.model.token.Project;
import com.tremolosecurity.unison.openstack.model.token.Token;
import com.tremolosecurity.unison.openstack.util.KSToken;

public class KeystoneProvisioningTarget implements UserStoreProvider {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(KeystoneProvisioningTarget.class.getName());
	
	String userName;
	String password;
	String domain;
	String url;
	String projectName;
	String projectDomainName;
	String usersDomain;

	private ConfigManager cfgMgr;
	
	
	@Override
	public void createUser(User user, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		KSUser newUser = new KSUser();
		newUser.setDomain_id(this.usersDomain);
		newUser.setName(user.getUserID());
		newUser.setEnabled(true);
		
		if (attributes.contains("email") && user.getAttribs().containsKey("email")) {
			newUser.setEmail(user.getAttribs().get("email").getValues().get(0));
		}
		
		if (attributes.contains("description") && user.getAttribs().containsKey("description")) {
			newUser.setEmail(user.getAttribs().get("description").getValues().get(0));
		}
		
		HttpCon con = null;
		KSUser fromKS = null;
		try {
			con = this.createClient();
			KSToken token = this.getToken(con);
			Gson gson = new Gson();
			UserHolder userHolder = new UserHolder();
			userHolder.setUser(newUser);
			String json = gson.toJson(userHolder);
			System.err.println(json);
			StringBuffer b = new StringBuffer();
			b.append(this.url).append("/users");
			json = this.callWSPost(token.getAuthToken(), con,b.toString() , json);
			if (json == null) {
				throw new Exception("Could not create user");
			}
			
			UserHolder createdUser = gson.fromJson(json, UserHolder.class);
			
			for (String group : user.getGroups()) {
				String groupID = this.getGroupID(token.getAuthToken(), con, group);
				b.setLength(0);
				b.append(this.url).append("/groups/").append(groupID).append("/users/").append(createdUser.getUser().getId());
				this.callWSPutNoData(token.getAuthToken(), con, b.toString());
			
			}
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not work with keystone",e);
		} finally {
			if (con != null) {
				con.getBcm().shutdown();
			}
		}
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
		HttpCon con = null;
		KSUser fromKS = null;
		try {
			con = this.createClient();
			KSToken token = this.getToken(con);
			
			String id;
			if (user.getAttribs().get("id") != null) {
				id = user.getAttribs().get("id").getValues().get(0);
			} else {
				HashSet<String> attrs = new HashSet<String>();
				attrs.add("id");
				User userFromKS = this.findUser(user.getUserID(), attrs, request);
				id = userFromKS.getAttribs().get("id").getValues().get(0);
			}
			
			StringBuffer b = new StringBuffer(this.url).append("/users/").append(id);
			this.callWSDelete(token.getAuthToken(), con, b.toString());
		} catch (Exception e) {
			throw new ProvisioningException("Could not work with keystone",e);
		} finally {
			if (con != null) {
				con.getBcm().shutdown();
			}
		}
	}

	@Override
	public User findUser(String userID, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		
		
		HttpCon con = null;
		KSUser fromKS = null;
		try {
			con = this.createClient();
			KSToken token = this.getToken(con);
			
			List<NameValuePair> qparams = new ArrayList<NameValuePair>();
			qparams.add(new BasicNameValuePair("domain_id",this.usersDomain));
			qparams.add(new BasicNameValuePair("name",userID));
			
			StringBuffer b = new StringBuffer();
			b.append(this.url).append("/users?").append(URLEncodedUtils.format(qparams, "UTF-8"));
			String fullURL = b.toString();
			String json = this.callWS(token.getAuthToken(), con, fullURL);
			Gson gson = new Gson();
			UserLookupResponse resp = gson.fromJson(json, UserLookupResponse.class);
			
			if (resp.getUsers().isEmpty()) {
				return null;
			} else {
				fromKS = resp.getUsers().get(0);
				
				User user = new User(fromKS.getName());
				
				if (attributes.contains("name")) {
					user.getAttribs().put("name", new Attribute("name",fromKS.getName()));
				}
				
				if (attributes.contains("id")) {
					user.getAttribs().put("id", new Attribute("id",fromKS.getId()));
				}
				
				if (attributes.contains("email") && fromKS.getEmail() != null) {
					user.getAttribs().put("email", new Attribute("email",fromKS.getEmail()));
				}
				
				if (attributes.contains("description") && fromKS.getDescription() != null) {
					user.getAttribs().put("description", new Attribute("description",fromKS.getEmail()));
				}
				
				
				
				if (attributes.contains("enabled")) {
					user.getAttribs().put("enabled", new Attribute("enabled",Boolean.toString(fromKS.getEnabled())));
				}
				
				
				b.setLength(0);
				b.append(this.url).append("/users/").append(fromKS.getId()).append("/groups");
				json = this.callWS(token.getAuthToken(), con, b.toString());
				
				GroupLookupResponse gresp = gson.fromJson(json, GroupLookupResponse.class);
				
				for (KSGroup group : gresp.getGroups()) {
					user.getGroups().add(group.getName());
				}
				
				
				if (attributes.contains("roles")) {
					b.setLength(0);
					b.append(this.url).append("/role_assignments?user.id=").append(fromKS.getId()).append("&include_names=true");
					json = this.callWS(token.getAuthToken(), con, b.toString());
					
					RoleAssignmentResponse rar = gson.fromJson(json, RoleAssignmentResponse.class);
					Attribute attr = new Attribute("roles");
					for (KSRoleAssignment role : rar.getRole_assignments()) {
						if (role.getScope().getProject() != null) {
							attr.getValues().add(gson.toJson(new Role(role.getRole().getName(),"project",role.getScope().getProject().getDomain().getName(),role.getScope().getProject().getName())));
						} else {
							attr.getValues().add(gson.toJson(new Role(role.getRole().getName(),"domain",role.getScope().getDomain().getName())));
						}
					}
					
					user.getAttribs().put("roles", attr);
				
				}
				
				
				return user;
			}
			
			
			
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not work with keystone",e);
		} finally {
			if (con != null) {
				con.getBcm().shutdown();
			}
		}
		
		
		
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
	

	
	@Override
	public void init(Map<String, Attribute> cfg, ConfigManager cfgMgr, String name) throws ProvisioningException {
		this.url = this.loadOption("url", cfg, false);
		this.userName = this.loadOption("userName", cfg, false);
		this.password = this.loadOption("password", cfg, true);
		this.domain = this.loadOption("domain", cfg, false);
		this.projectDomainName = this.loadOption("projectDomainName", cfg, false);
		this.projectName = this.loadOption("projectName", cfg, false);
		this.usersDomain = this.loadOption("usersDomain", cfg, false);
		
		this.cfgMgr = cfgMgr;
	}
	
	public KSToken getToken(HttpCon con) throws Exception {
		Gson gson = new Gson();
		StringBuffer b = new StringBuffer();
		b.append(this.url).append("/auth/tokens");
		
		HttpPost put = new HttpPost(b.toString());
		
		TokenRequest req = new TokenRequest();
		req.getAuth().getIdentity().getMethods().add("password");
		req.getAuth().getIdentity().getPassword().getUser().getDomain().setName(this.domain);
		req.getAuth().getIdentity().getPassword().getUser().setName(this.userName);
		req.getAuth().getIdentity().getPassword().getUser().setPassword(this.password);
		req.getAuth().getScope().setProject(new Project());
		req.getAuth().getScope().getProject().setName(this.projectName);
		req.getAuth().getScope().getProject().setDomain(new KSDomain());
		req.getAuth().getScope().getProject().getDomain().setName(this.projectDomainName);
		
		String json = gson.toJson(req);
		
		StringEntity str = new StringEntity(json,ContentType.APPLICATION_JSON);
		put.setEntity(str);
		
		HttpResponse resp = con.getHttp().execute(put);
		
		if (resp.getStatusLine().getStatusCode() == 201) {
			json = EntityUtils.toString(resp.getEntity());
			TokenResponse token = gson.fromJson(json, TokenResponse.class);
			String authToken = resp.getHeaders("X-Subject-Token")[0].getValue();
			
			return new KSToken(authToken,token.getToken());
		} else {
			throw new Exception("Could not authenticate to keystone");
		}
			
	}
	
	public HttpCon createClient() throws Exception {
		ArrayList<Header> defheaders = new ArrayList<Header>();
		

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
	
	public String callWS(String token, HttpCon con,String uri) throws IOException, ClientProtocolException {
		
		
		
		HttpGet get = new HttpGet(uri);
		get.addHeader(new BasicHeader("X-Auth-Token",token));
		HttpResponse resp = con.getHttp().execute(get);
		String json = EntityUtils.toString(resp.getEntity());
		return json;
	}
	
	public boolean callWSPutNoData(String token, HttpCon con,String uri) throws IOException, ClientProtocolException {
		
		
		
		HttpPut get = new HttpPut(uri);
		get.addHeader(new BasicHeader("X-Auth-Token",token));
		HttpResponse resp = con.getHttp().execute(get);
		return resp.getStatusLine().getStatusCode() == 204;
	}
	
	public String callWSDelete(String token, HttpCon con,String uri) throws IOException, ClientProtocolException {
		
		
		
		HttpDelete del = new HttpDelete(uri);
		del.addHeader(new BasicHeader("X-Auth-Token",token));
		HttpResponse resp = con.getHttp().execute(del);
		String json = EntityUtils.toString(resp.getEntity());
		return json;
	}
	
	private String callWSPost(String token, HttpCon con,String uri,String json) throws IOException, ClientProtocolException {
		
		HttpPost put = new HttpPost(uri);
		
		put.addHeader(new BasicHeader("X-Auth-Token",token));
		
		StringEntity str = new StringEntity(json,ContentType.APPLICATION_JSON);
		put.setEntity(str);
		
		HttpResponse resp = con.getHttp().execute(put);
		
		json = EntityUtils.toString(resp.getEntity());
		return json;
	}
	
	private String getGroupID(String token,HttpCon con,String name) throws Exception {
		StringBuffer b = new StringBuffer();
		b.append(this.url).append("/groups?name=").append(URLEncoder.encode(name, "UTF-8"));
		String json = this.callWS(token, con, b.toString());
		Gson gson = new Gson();
		GroupResponse resp = gson.fromJson(json, GroupResponse.class);
		if (resp.getGroups().isEmpty()) {
			return null;
		} else {
			return resp.getGroups().get(0).getId();
		}
	}

}
