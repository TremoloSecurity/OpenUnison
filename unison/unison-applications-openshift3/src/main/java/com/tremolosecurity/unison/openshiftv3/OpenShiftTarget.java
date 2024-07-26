/*******************************************************************************
 * Copyright 2016, 2018 Tremolo Security, Inc.
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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

import javax.jms.JMSException;
import javax.jms.TextMessage;

import org.apache.commons.net.util.Base64;
import org.apache.http.Consts;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.apache.logging.log4j.Logger;
import org.cryptacular.EncodingException;
import org.cryptacular.StreamException;
import org.cryptacular.util.CertUtil;
import org.joda.time.DateTime;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.ibm.icu.impl.UResource.Array;
import com.tremolosecurity.certs.CertManager;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.ApplicationType;
import com.tremolosecurity.config.xml.ParamType;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.ProvisioningTarget;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.UserStoreProvider;
import com.tremolosecurity.provisioning.core.UserStoreProviderWithAddGroup;
import com.tremolosecurity.provisioning.core.UserStoreProviderWithMetadata;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.jms.JMSConnectionFactory;
import com.tremolosecurity.provisioning.jms.JMSSessionHolder;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.provisioning.util.EncryptedMessage;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.openshiftv3.cache.K8sApis;
import com.tremolosecurity.unison.openshiftv3.dr.DisasterRecoveryAction;
import com.tremolosecurity.unison.openshiftv3.model.Item;
import com.tremolosecurity.unison.openshiftv3.model.Response;
import com.tremolosecurity.unison.openshiftv3.model.groups.GroupItem;


public class OpenShiftTarget implements UserStoreProviderWithAddGroup,UserStoreProviderWithMetadata {
	
	public enum TokenType {
		NONE,
		STATIC,
		LEGACY,
		TOKENAPI,
		OIDC,
		CERTIFICATE
	}
	
	private TokenType tokenType;

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(OpenShiftTarget.class.getName());

	String url;
	String userName;
	String password;

	private ConfigManager cfgMgr;

	private String name;

	private boolean useToken;

	private String osToken;

	private boolean localToken;

	private String tokenPath;
	private DateTime tokenExpires;
	
	private String oidcIdp;
	private String oidcTrustName;
	private String oidcIssuer;
	private String oidcSub;
	private String oidcCertName;

	private String oidcAudience;

	private String oidcIssuerHost;
	
	String label;
	
	String gitUrl;
	
	List<JMSSessionHolder> drQueues;
	
	private boolean useDefaultCaPath;
	
	
	boolean oidcTokenInitialized;
	Map<String, Attribute> cfg;

	private boolean useCertificate;

	private String certSecretLocation;
	
	boolean loadedCert;
	
	
	private Map<String,String> annotations;
	private Map<String,String> labels;

	private K8sApis k8sApi;

	@Override
	public void createUser(User user, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		com.tremolosecurity.unison.openshiftv3.model.users.User osUser = new com.tremolosecurity.unison.openshiftv3.model.users.User();
		
		
		osUser.setKind("User");
		osUser.setApiVersion("user.openshift.io/v1");
		osUser.getMetadata().put("name", user.getUserID());
		if (user.getAttribs().get("fullName") != null) {
			osUser.setFullName(user.getAttribs().get("fullName").getValues().get(0));
		}
		
		Gson gson  = new Gson();
		
		try {
			String token = this.getAuthToken();
			
			
			HttpCon con = this.createClient();
			try {
				String json = gson.toJson(osUser);
				StringBuffer b = new StringBuffer();
				b.append("/apis/user.openshift.io/v1/users");
				osUser = gson.fromJson(this.callWSPost(token, con, b.toString(), json),com.tremolosecurity.unison.openshiftv3.model.users.User.class);
				
				if (! osUser.getKind().equals("User")) {
					throw new ProvisioningException("Could not create user " + user.getUserID() + " - " + osUser.getReason());
				}
				
		
				this.cfgMgr.getProvisioningEngine().logAction(name,true, ActionType.Add,  approvalID, workflow, "name", user.getUserID());
				this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Add,  approvalID, workflow, "name", (String) osUser.getMetadata().get("name"));
				
				if (user.getAttribs().get("fullName") != null) {
					this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Add,  approvalID, workflow, "fullName", osUser.getFullName());
				}
				
				
				
				
				
				for (String groupName : user.getGroups()) {
					this.addUserToGroup(token, con, user.getUserID(), groupName, approvalID, workflow);
				}
				
			} finally {
				if (con != null) {
					con.getBcm().shutdown();
				}
			}
		} catch (Exception e) {
			throw new ProvisioningException("Could not create user",e);
		}
		

	}

	@Override
	public void setUserPassword(User user, Map<String, Object> request) throws ProvisioningException {
		throw new ProvisioningException("Not supported");

	}

	@Override
	public void syncUser(User user, boolean addOnly, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		Gson gson = new Gson();
		User fromServer = this.findUser(user.getUserID(), attributes, request);
		if (fromServer == null) {
			this.createUser(user, attributes, request);
		} else {
			StringBuffer b = new StringBuffer();
			String token = null;
			
			if (attributes.contains("fullName")) {
				if (user.getAttribs().get("fullName") != null) {
					String fullName = user.getAttribs().get("fullName").getValues().get(0);
					String fromServerFullName = fromServer.getAttribs().get("fullName") != null ? fromServer.getAttribs().get("fullName").getValues().get(0) : null;
					
					if (fromServerFullName == null || ! fromServerFullName.equalsIgnoreCase(fullName)) {
						try {
							token = setFullName(user, approvalID, workflow, gson, b);
						} catch (Exception e) {
							throw new ProvisioningException("Could not set fullName from " + user.getUserID(),e);
						}
					}
				} else {
					if (! addOnly) {
						try {
							token = deleteFullName(user, approvalID, workflow, gson, b);
						} catch (Exception e) {
							throw new ProvisioningException("Could not delete fullName from " + user.getUserID(),e);
						}
					}
				}
			}
			
			
			
			try {
				syncGroups(user, addOnly, approvalID, workflow, fromServer, token);
			} catch (Exception e) {
				throw new ProvisioningException("Could not sync groups for " + user.getUserID(),e);
			}
			
		}

	}

	private void syncGroups(User user, boolean addOnly, int approvalID, Workflow workflow, User fromServer,
			String token) throws Exception, IOException {
		HttpCon con = null;
		
		try {
			//first see if there are groups to add
			HashSet<String> fromServerGroups = new HashSet<String>();
			fromServerGroups.addAll(fromServer.getGroups());
			for (String groupName : user.getGroups()) {
				if (! fromServerGroups.contains(groupName)) {
					
					if (token == null) {
						token = this.getAuthToken();
					}
					
					if (con == null) {
						con = this.createClient();
					}
					
					this.addUserToGroup(token, con, user.getUserID(), groupName, approvalID, workflow);
				}
			}
			
			if (! addOnly) {
				//remove groups no longer present
				HashSet<String> fromUserGroups = new HashSet<String>();
				fromUserGroups.addAll(user.getGroups());
				
				for (String groupName : fromServer.getGroups()) {
					if (! fromUserGroups.contains(groupName)) {
						if (token == null) {
							token = this.getAuthToken();
						}
						
						if (con == null) {
							con = this.createClient();
						}
						
						this.removeUserFromGroup(token, con, user.getUserID(), groupName, approvalID, workflow);
					}
				}
			}
			
			
		} finally {
			if (con != null) {
				con.getBcm().shutdown();
				con.getHttp().close();
			}
		}
	}

	private String deleteFullName(User user, int approvalID, Workflow workflow, Gson gson, StringBuffer b)
			throws Exception, IOException, ClientProtocolException, ProvisioningException {
		String token;
		token = this.getAuthToken();
		HttpCon con = this.createClient();
		try {
			b.append("/apis/user.openshift.io/v1/users/").append(user.getUserID());
			String json = callWS(token,con,b.toString());
			com.tremolosecurity.unison.openshiftv3.model.users.User osUser = gson.fromJson(json, com.tremolosecurity.unison.openshiftv3.model.users.User.class);
			osUser.setFullName(null);
			json = gson.toJson(osUser);
			json = callWSPut(token,con,b.toString(),json);
			osUser = gson.fromJson(json, com.tremolosecurity.unison.openshiftv3.model.users.User.class);
			
			if (osUser.getKind().equals("User")) {
				this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Delete,  approvalID, workflow, "fullName", osUser.getFullName());
			} else {
				throw new Exception("Could not unset fullName for " + user.getUserID() + " - " + osUser.getReason());
			}
			
		} finally {
			
			con.getHttp().close();
			con.getBcm().shutdown();
		}
		
		return token;
	}
	
	
	private String setFullName(User user, int approvalID, Workflow workflow, Gson gson, StringBuffer b)
			throws Exception, IOException, ClientProtocolException, ProvisioningException {
		String token;
		token = this.getAuthToken();
		HttpCon con = this.createClient();
		try {
			b.append("/apis/user.openshift.io/v1/users/").append(user.getUserID());
			String json = callWS(token,con,b.toString());
			com.tremolosecurity.unison.openshiftv3.model.users.User osUser = gson.fromJson(json, com.tremolosecurity.unison.openshiftv3.model.users.User.class);
			osUser.setFullName(user.getAttribs().get("fullName").getValues().get(0));
			json = gson.toJson(osUser);
			json = callWSPut(token,con,b.toString(),json);
			osUser = gson.fromJson(json, com.tremolosecurity.unison.openshiftv3.model.users.User.class);
			
			if (osUser.getKind().equals("User")) {
				this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Replace,  approvalID, workflow, "fullName", osUser.getFullName());
			} else {
				throw new Exception("Could not set fullName for " + user.getUserID() + " - " + osUser.getReason());
			}
			
		} finally {
			
			con.getHttp().close();
			con.getBcm().shutdown();
		}
		
		return token;
	}

	@Override
	public void deleteUser(User user, Map<String, Object> request) throws ProvisioningException {
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		user = this.findUser(user.getUserID(), new HashSet<String>(), request);
		
		try {
			String token = this.getAuthToken();
			HttpCon con = this.createClient();
			Gson gson = new Gson();
			try {
				StringBuffer b = new StringBuffer();
				b.append("/apis/user.openshift.io/v1/users/").append(user.getUserID());
				String json = this.callWSDelete(token, con, b.toString());
				Response resp = gson.fromJson(json, Response.class);
				if (resp.getStatus() != null && ! resp.getStatus().equalsIgnoreCase("success")) {
					throw new Exception("Unable to delete " + user.getUserID() + " - " + resp.getReason());
				}
				
				this.cfgMgr.getProvisioningEngine().logAction(name,true, ActionType.Delete,  approvalID, workflow, "name", user.getUserID());
				
				for (String group : user.getGroups()) {
					this.removeUserFromGroup(token, con, user.getUserID(), group, approvalID, workflow);
				}
			} finally {
				if (con != null) {
					con.getBcm().shutdown();
					con.getHttp().close();
				}
			}
		} catch (Exception e) {
			throw new ProvisioningException("Could not delete user " + user.getUserID());
		} 
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
				
				String json = callWS(token, con,"/apis/user.openshift.io/v1/groups");
				Gson gson = new Gson();
				TypeToken<com.tremolosecurity.unison.openshiftv3.model.List<GroupItem>> tokenType = new TypeToken<com.tremolosecurity.unison.openshiftv3.model.List<GroupItem>>() {};
				groupList = gson.fromJson(json, tokenType.getType());
				
				b.append("/apis/user.openshift.io/v1/users/").append(userID);
				json = callWS(token,con,b.toString());
				
				
				com.tremolosecurity.unison.openshiftv3.model.users.User osUser = gson.fromJson(json, com.tremolosecurity.unison.openshiftv3.model.users.User.class);
				
				if (osUser.getKind().equalsIgnoreCase("User")) {
				
					user = new User(userID);
					
					for (String attrName : osUser.getMetadata().keySet()) {
						if (! attrName.equalsIgnoreCase("fullName") && attributes.contains(attrName)) {
							user.getAttribs().put(attrName, new Attribute(attrName,(String) osUser.getMetadata().get(attrName)));
						}
					}
					
					if (attributes.contains("fullName") && osUser.getFullName() != null) {
						user.getAttribs().put("fullName", new Attribute("fullName",osUser.getFullName()));
					}
				}
				
			} finally {
				if (con != null) {
					con.getBcm().shutdown();
				}
			}
			
			for (GroupItem group : groupList.getItems()) {
				if (group.getUsers() != null && group.getUsers().contains(userID)) {
					groupsForUser.add((String) group.getMetadata().get("name"));
				}
			}
			
			if (groupsForUser.isEmpty()) {
				return user;
			} else {
				if (user == null) {
					//user = new User(userID);
					return null;
				}
				user.getGroups().addAll(groupsForUser);
				return user;
			}
		} catch (Exception e) {
			throw new ProvisioningException("Could not load " + userID,e);
		}
	}

	public String callWS(String token, HttpCon con,String uri) throws IOException, ClientProtocolException {
		StringBuffer b = new StringBuffer();
		
		b.append(this.getUrl()).append(uri);
		HttpGet get = new HttpGet(b.toString());
		
		if (token != null) {
			b.setLength(0);
			b.append("Bearer ").append(token);
			get.addHeader(new BasicHeader("Authorization","Bearer " + token));
		}
		
		HttpResponse resp = con.getHttp().execute(get);
		
		
		
		String json = EntityUtils.toString(resp.getEntity());
		
		
		if (resp.getStatusLine().getStatusCode() >= 200 && resp.getStatusLine().getStatusCode() <= 299 ) {
			return json;
		} else if (resp.getStatusLine().getStatusCode() != 404) {
			StringBuilder sb = new StringBuilder();
			sb.append("Unexpected result calling '").append(get.getURI()).append("' - ").append(resp.getStatusLine().getStatusCode()).append(" / ").append(json);
			throw new IOException(sb.toString());
		} else  {
			if (logger.isDebugEnabled()) {
				logger.debug("Unexpected result calling '" + get.getURI() + "' - " + resp.getStatusLine().getStatusCode() + " / " + json);
			}
			return json;
		}
		
		
	}

	public boolean isObjectExists(String token, HttpCon con,String uri,String json) throws IOException, ClientProtocolException,ProvisioningException, ParseException {
		
		JSONParser parser = new JSONParser();
		JSONObject root = (JSONObject) parser.parse(json);
		JSONObject metadata = (JSONObject) root.get("metadata");

		String name = (String) metadata.get("name");

		
		
		StringBuffer b = new StringBuffer();
		
		b.append(uri).append('/').append(name);
		
		
		json = this.callWS(token, con, b.toString());
		

		root = (JSONObject) parser.parse(json);
		if (root.containsKey("kind") && root.get("kind").equals("Status") && ((Long) root.get("code")) == 404) {
			return false;
		} else {
			return true;
		}
			

		
		
	}
	
	public boolean isObjectExistsByName(String token, HttpCon con,String uri,String name) throws IOException, ClientProtocolException,ProvisioningException, ParseException {
		
		JSONParser parser = new JSONParser();
		
		

		
		
		StringBuffer b = new StringBuffer();
		
		b.append(uri).append('/').append(name);
		
		
		String json = this.callWS(token, con, b.toString());
		

		JSONObject root = (JSONObject) parser.parse(json);
		if (root.containsKey("kind") && root.get("kind").equals("Status") && ((Long) root.get("code")) == 404) {
			return false;
		} else {
			return true;
		}
			

		
		
	}
	
	public boolean isObjectExistsByPath(String token, HttpCon con,String uri) throws IOException, ClientProtocolException,ProvisioningException, ParseException {
		
		JSONParser parser = new JSONParser();
		
		

		
		
		StringBuffer b = new StringBuffer();
		
		b.append(uri);
		
		
		String json = this.callWS(token, con, b.toString());
		
		if (json.startsWith("404")) {
			return false;
		}

		JSONObject root = (JSONObject) parser.parse(json);
		if (root.containsKey("kind") && root.get("kind").equals("Status") && ((Long) root.get("code")) == 404) {
			return false;
		} else {
			return true;
		}
			

		
		
	}
	
	public String callWSDelete(String token, HttpCon con,String uri) throws IOException, ClientProtocolException {
		String objToDeleteJson = "";
		if (this.drQueues.size() > 0) {
			try {
				if (this.isObjectExistsByPath(token, con, uri)) {
					objToDeleteJson = this.callWS(token, con, uri);
				} 
			} catch (IOException | ProvisioningException | ParseException e) {
				throw new IOException("Could not delete object " + uri,e);
			}
		}
		
		
		
		StringBuffer b = new StringBuffer();
		
		b.append(this.getUrl()).append(uri);
		HttpDelete get = new HttpDelete(b.toString());
		
		if (token != null) {
			b.setLength(0);
			b.append("Bearer ").append(token);
			get.addHeader(new BasicHeader("Authorization","Bearer " + token));
		}
		
		HttpResponse resp = con.getHttp().execute(get);
		
		if (resp.getStatusLine().getStatusCode() >= 200 && resp.getStatusLine().getStatusCode() < 300) {
			
			try {
				if (! objToDeleteJson.isEmpty()) {
					boolean ignore = determineIgnoreDr(objToDeleteJson);
					if (! ignore) {
						this.sendtoDRQueue(uri, "DELETE", objToDeleteJson);
					}
				}
			} catch (ProvisioningException | JMSException | ParseException e) {
				throw new IOException("Could not send to dr queues",e);
			}
		}
		
		String json = EntityUtils.toString(resp.getEntity());
		return json;
	}
	
	public String callWSPut(String token, HttpCon con,String uri,String json) throws IOException, ClientProtocolException {
		
		String objToPatch = "";
		if (this.drQueues.size() > 0) {
			try {
				if (this.isObjectExistsByPath(token, con, uri)) {
					objToPatch = this.callWS(token, con, uri);
				} 
			} catch (IOException | ProvisioningException | ParseException e) {
				throw new IOException("Could not delete object " + uri,e);
			}
		}
		
		StringBuffer b = new StringBuffer();
		
		b.append(this.getUrl()).append(uri);
		HttpPut put = new HttpPut(b.toString());
		
		if (token != null) {
			b.setLength(0);
			b.append("Bearer ").append(token);
			put.addHeader(new BasicHeader("Authorization","Bearer " + token));
		}
		
		StringEntity str = new StringEntity(json,ContentType.APPLICATION_JSON);
		put.setEntity(str);
		
		HttpResponse resp = con.getHttp().execute(put);
		
		if (resp.getStatusLine().getStatusCode() >= 200 && resp.getStatusLine().getStatusCode() < 300) {
			
			try {
				if (! objToPatch.isEmpty()) {
					boolean ignore = determineIgnoreDr(objToPatch);
					if (! ignore) {
						this.sendtoDRQueue(uri, "PUT", json);
					}
				}
			} catch (ProvisioningException | JMSException | ParseException e) {
				throw new IOException("Could not send to dr queues",e);
			}
		}
		
		json = EntityUtils.toString(resp.getEntity());
		return json;
	}
	
	public String callWSPatchJson(String token, HttpCon con,String uri,String json) throws IOException, ClientProtocolException {
		return this.callWSPatchJson(token, con, uri, json, "application/merge-patch+json");
	}
	
	public String callWSPatchJson(String token, HttpCon con,String uri,String json,String contentType) throws IOException, ClientProtocolException {
		String objToPatch = "";
		if (this.drQueues.size() > 0) {
			try {
				if (this.isObjectExistsByPath(token, con, uri)) {
					objToPatch = this.callWS(token, con, uri);
				} 
			} catch (IOException | ProvisioningException | ParseException e) {
				throw new IOException("Could not delete object " + uri,e);
			}
		}
		
		StringBuffer b = new StringBuffer();
		
		b.append(this.getUrl()).append(uri);
		HttpPatch put = new HttpPatch(b.toString());
		
		if (token != null) {
			b.setLength(0);
			b.append("Bearer ").append(token);
			put.addHeader(new BasicHeader("Authorization","Bearer " + token));
		}
		
		StringEntity str = new StringEntity(json,ContentType.create(contentType,Consts.UTF_8));
		put.setEntity(str);
		
		HttpResponse resp = con.getHttp().execute(put);
		
		if (resp.getStatusLine().getStatusCode() >= 200 && resp.getStatusLine().getStatusCode() < 300) {
			
			try {
				if (! objToPatch.isEmpty()) {
					boolean ignore = determineIgnoreDr(objToPatch);
					if (! ignore) {
						this.sendtoDRQueue(uri, "PATCH", json,contentType);
					}
				}
			} catch (ProvisioningException | JMSException | ParseException e) {
				throw new IOException("Could not send to dr queues",e);
			}
		}
		
		json = EntityUtils.toString(resp.getEntity());
		return json;
	}
	
	
	private void sendtoDRQueue(String uri,String method,String json) throws ProvisioningException, JMSException {
		this.sendtoDRQueue(uri, method, json, null);
		
	}
	
	private void sendtoDRQueue(String uri,String method,String json,String contentType) throws ProvisioningException, JMSException {
		logger.info("DR Queues Size : " + this.drQueues.size());
		if (this.drQueues.size() > 0) {
			DisasterRecoveryAction dr = new DisasterRecoveryAction();
			
			dr.setMethod(method);
			dr.setUrl(uri);
			dr.setJson(json);
			dr.setContentType(contentType);
			
			logger.info("Encrypting and enqueueing " + dr.toString());
			
			Gson gson = new Gson();
			
			EncryptedMessage encJson = this.cfgMgr.getProvisioningEngine().encryptObject(dr);
			for (JMSSessionHolder session : this.drQueues) {
				synchronized (session) {
					logger.info("Sending to " + session.getQueueName());
					TextMessage tm = session.getSession().createTextMessage(gson.toJson(encJson));
					tm.setStringProperty("JMSXGroupID", "unison-kubernetes");
					session.getMessageProduceer().send(tm);
				}
			}
		}
	}
	
	public String callWSPost(String token, HttpCon con,String uri,String json) throws IOException, ClientProtocolException {
		StringBuffer b = new StringBuffer();
		
		b.append(this.getUrl()).append(uri);
		HttpPost put = new HttpPost(b.toString());
		
		if (token != null) {
			b.setLength(0);
			b.append("Bearer ").append(token);
			put.addHeader(new BasicHeader("Authorization","Bearer " + token));
		}
		
		StringEntity str = new StringEntity(json,ContentType.APPLICATION_JSON);
		
		
		
		
		put.setEntity(str);
		
		HttpResponse resp = con.getHttp().execute(put);
		
		if (resp.getStatusLine().getStatusCode() >= 200 && resp.getStatusLine().getStatusCode() < 300) {
			try {
				boolean ignore = determineIgnoreDr(json);
				if (! ignore) {
					this.sendtoDRQueue(uri, "POST", json);
				}
			} catch (ProvisioningException | JMSException | ParseException e) {
				throw new IOException("Could not send to dr queues",e);
			}
		}
		
		
		json = EntityUtils.toString(resp.getEntity());
		return json;
	}

	private boolean determineIgnoreDr(String json) throws ParseException {
		boolean ignore = false;
		JSONObject root = (JSONObject) new JSONParser().parse(json);
		JSONObject metadata = (JSONObject) root.get("metadata");
		if (metadata != null) {
			JSONObject annotations = (JSONObject) metadata.get("annotations");
			if (annotations != null) {
				String ignoreAnnotation = (String) annotations.get("tremolo.io/dr-ignore");
				if (ignoreAnnotation != null && ignoreAnnotation.equalsIgnoreCase("true")) {
					ignore = true;
				}
			}
		}
		return ignore;
	}

	@Override
	public void init(Map<String, Attribute> cfg, ConfigManager cfgMgr, String name) throws ProvisioningException {
		this.cfg = cfg;
		this.useCertificate = false;
		this.url = this.loadOption("url", cfg, false);
		this.name = name;
		
		this.annotations = new HashMap<String,String>();
		this.labels = new HashMap<String,String>();
		
		this.useDefaultCaPath = false;
		
		String tmpUseToken = this.loadOptionalAttributeValue("useToken", "Use Token", cfg,null);
		this.useToken = tmpUseToken != null && tmpUseToken.equalsIgnoreCase("true");
		
		String localTokenType = this.loadOptionalAttributeValue("tokenType", "tokenType",cfg,null);
		if (localTokenType != null) {
			this.tokenType = TokenType.valueOf(localTokenType.toUpperCase());
		} else {
			this.tokenType = TokenType.LEGACY;
		}
		
		
		if (! useToken && this.tokenType != TokenType.CERTIFICATE) {
			this.userName = this.loadOption("userName", cfg, false);
			this.password = this.loadOption("password", cfg, true);
		} else {
			
		
			
			
			if (localTokenType == null || localTokenType.trim().isEmpty()) {
				localTokenType = "LEGACY";
			}
			
			
			
			switch (tokenType) {
				case STATIC:  this.osToken = this.loadOptionalAttributeValue("token", "Token",cfg,"***************************"); break;
				case LEGACY:
					try {
						this.osToken = new String(Files.readAllBytes(Paths.get("/var/run/secrets/kubernetes.io/serviceaccount/token")), StandardCharsets.UTF_8);
					} catch (IOException e) {
						throw new ProvisioningException("Could not load token",e);
					}
					
					// check if token is projected, starting in 1.21 this is the default
					
					int firstPeriod = this.osToken.indexOf('.');
					int lastPeriod = this.osToken.lastIndexOf('.');
					
					String json = new String(Base64.decodeBase64(this.osToken.substring(firstPeriod + 1,lastPeriod)));
					try {
						JSONObject claims = (JSONObject) new JSONParser().parse(json);
						
						if (claims.containsKey("exp")) {
							logger.info("Default token is projected, switching to TokenAPI");
							this.tokenType = TokenType.TOKENAPI;
							this.tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token";
							this.useDefaultCaPath = true;
							this.checkProjectedToken();
						}
						
					} catch (ParseException e1) {
						throw new ProvisioningException("Could not load token",e1);
					}
					
					break;
				case TOKENAPI:
					this.tokenPath = this.loadOption("tokenPath", cfg, false);
					this.checkProjectedToken();
					
					break;
				case NONE:
					break;
				case OIDC:
					this.oidcTokenInitialized = false;
					this.initRemoteOidc(cfg, cfgMgr, localTokenType);
					break;
				case CERTIFICATE:
					this.useCertificate = true;
					this.loadedCert = false;
					this.certSecretLocation = this.loadOptionalAttributeValue("certSecretURI", "certSecretURI", cfg, null);
					try {
						this.loadRemoteKeyMaterial(cfgMgr,this.certSecretLocation);
					} catch (Exception e) {
						throw new ProvisioningException("Could not load remote key data",e);
					}
					break;
					
			}
			
			
			
			if (this.url.isEmpty() || this.url.equalsIgnoreCase("https://kubernetes.default.svc")) {
				this.localToken = true;
				
				
				String certAlias = this.loadOptionalAttributeValue("caCertAlias","caCertAlias", cfg,null);
				if (certAlias == null) {
					certAlias = "k8s-master";
				}
				
				try {
					logger.info("Cert Alias Storing - '" + certAlias + "'");
					X509Certificate cert = null;
					if (tokenType == TokenType.LEGACY || this.useDefaultCaPath) {
						cert = CertUtil.readCertificate("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt");
					} else if (tokenType == TokenType.TOKENAPI) {
						// -\("/)/-
						cert = CertUtil.readCertificate(this.loadOption("certPath", cfg, false));
					}
					
					logger.info("Certificate - " + cert);
					
					cfgMgr.getKeyStore().setCertificateEntry(certAlias, cert);
				} catch (KeyStoreException | EncodingException | StreamException e) {
					throw new ProvisioningException("Could not load ca cert",e);
				}
				
			}
			
			
		}

		
		
		this.cfgMgr = cfgMgr;
		
		
		if (cfg.get("certificate") != null) {
			String certificate = cfg.get("certificate").getValues().get(0);
			try {
				X509Certificate cert = this.pem2cert(certificate);
				cfgMgr.getKeyStore().setCertificateEntry("k8s-certificate-" + this.name, cert);
			} catch (Exception e) {
				throw new ProvisioningException("Could not load certificate",e);
			}
			
		}
		
		try {
			cfgMgr.buildHttpConfig();
		} catch (KeyManagementException | UnrecoverableKeyException | NoSuchAlgorithmException | KeyStoreException e) {
			throw new ProvisioningException("Could not rebuild http configuration",e);
		}

		this.label = this.loadOptionalAttributeValue("label", "label", cfg, null);
		if (this.label == null) {
			this.label = this.name;
		}
		
		this.gitUrl = this.loadOptionalAttributeValue("gitUrl", "gitUrl", cfg, null);
		
		String drQueueNames = this.loadOptionalAttributeValue("drqueues","drqueues", cfg, null);
		this.drQueues = new ArrayList<JMSSessionHolder>();
		if (drQueueNames != null) {
			StringTokenizer toker = new StringTokenizer(drQueueNames,",",false);
			while (toker.hasMoreTokens()) {
				String queueName = toker.nextToken();
				this.drQueues.add(JMSConnectionFactory.getConnectionFactory().getSession(queueName));
			}
			
			
			
		}
		
		this.annotations = new HashMap<String,String>();
		this.labels = new HashMap<String,String>();
		
		this.k8sApi = new K8sApis(this);
		
	}
	
	public K8sApis getApis() {
		return this.k8sApi;
	}
	
	private void initRemoteOidc(Map<String, Attribute> cfg, ConfigManager cfgMgr, String name) throws ProvisioningException {
		this.oidcIdp = this.loadOption("oidcIdp", cfg, false);
		this.oidcIssuerHost = this.loadOptionalAttributeValue("oidcIssuerHost", "oidcIssuerHost", cfg, null);
		this.oidcSub = this.loadOption("oidcSub", cfg, false);
		this.oidcAudience = this.loadOption("oidcAudience", cfg, false);
		
		for (ApplicationType at : cfgMgr.getCfg().getApplications().getApplication()) {
			if (at.getName().equals(this.oidcIdp)) {
				for (ParamType pt : at.getUrls().getUrl().get(0).getIdp().getParams()) {
					if (pt.getName().equals("jwtSigningKey")) {
						this.oidcTokenInitialized = true;
						this.oidcCertName = pt.getValue();
					}
				}
				
				if (this.oidcIssuerHost == null) {
					this.oidcIssuerHost = at.getUrls().getUrl().get(0).getHost().get(0);
				}
				
				this.oidcIssuer = "https://" + this.oidcIssuerHost + at.getUrls().getUrl().get(0).getUri();
				
			}
		}
		
		
		
	}

	private synchronized void checkProjectedToken() throws ProvisioningException {
		try {
			if (this.tokenExpires == null || this.tokenExpires.isBeforeNow()) {
				
				this.osToken = new String(Files.readAllBytes(Paths.get(this.tokenPath)), StandardCharsets.UTF_8);
				
				int firstPeriod = this.osToken.indexOf('.');
				int lastPeriod = this.osToken.lastIndexOf('.');
	
				String json = new String(Base64.decodeBase64(this.osToken.substring(firstPeriod + 1,lastPeriod)));
				JSONObject claims = (JSONObject) new JSONParser().parse(json);
				long exp = ((Long)claims.get("exp")) * 1000L;
				this.tokenExpires = new DateTime(exp);
				
				
			}
		} catch (Exception e) {
			throw new ProvisioningException("Could not generate new token",e);
		}
	}
	
	private String loadOptionalAttributeValue(String name,String label,Map<String, Attribute> config,String mask) throws ProvisioningException {
		Attribute attr = config.get(name);
		if (attr == null) {
			logger.warn(label + " not found");
			return null;
		}
		
		String val = attr.getValues().get(0);
		if (mask != null) {
			logger.info(label + ": '" + mask + "'");
		} else {
			logger.info(label + ": '" + val + "'");
		}
		
		
		return val;
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

	

	public HttpCon createClient() throws Exception {
		if (this.tokenType == TokenType.CERTIFICATE && ! this.loadedCert) {
			this.loadRemoteKeyMaterial(cfgMgr, this.certSecretLocation);
			cfgMgr.buildHttpConfig();
		}
		
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

	public String getAuthToken() throws Exception {
		HttpCon con = this.createClient();
		try {
			
			if (! this.useToken && this.tokenType != TokenType.CERTIFICATE) {
			
				StringBuffer b = new StringBuffer();
				b.append(this.getUrl()).append("/oauth/authorize?response_type=token&client_id=openshift-challenging-client");
				HttpGet get = new HttpGet(b.toString());
				b.setLength(0);
				b.append(this.userName).append(':').append(this.password);
				String b64 = Base64.encodeBase64String(b.toString().getBytes("UTF-8"));
				b.setLength(0);
				b.append("Basic ").append(b64.substring(0, b64.length() - 2));
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
			} else {
				
				switch (this.tokenType) {
					case CERTIFICATE:
						
						
					case NONE: return null;
					case TOKENAPI: this.checkProjectedToken();
					case LEGACY:
					case STATIC: return this.osToken;
					case OIDC: return this.generateOidcToken();
					
					default:
						throw new ProvisioningException("Unknown tokenType");
					
				}
				
				
			}
		} finally {
			if (con != null) {
				con.getBcm().shutdown();
			}
		}
	}

	private String generateOidcToken() throws JoseException {
		
		if (! this.oidcTokenInitialized) {
			logger.warn("OIDC tokens not initialized, initializing now");
			try {
				this.initRemoteOidc(this.cfg, GlobalEntries.getGlobalEntries().getConfigManager(), "OIDC");
			} catch (ProvisioningException e) {
				throw new JoseException("Could not initialize oidc",e);
			}
		}
		
		
		
		JwtClaims claims = new JwtClaims();
		claims.setIssuer(this.oidcIssuer);
		claims.setAudience(this.oidcAudience);
		claims.setExpirationTimeMinutesInTheFuture(1);
		claims.setNotBeforeMinutesInThePast(1);
		claims.setGeneratedJwtId();
		claims.setIssuedAtToNow();
		claims.setSubject(this.oidcSub);
		
		JsonWebSignature jws = new JsonWebSignature();
		jws.setPayload(claims.toJson());
		jws.setKey(this.cfgMgr.getPrivateKey(this.oidcCertName));
		jws.setKeyIdHeaderValue(this.buildKID(this.cfgMgr.getCertificate(this.oidcCertName)));
		jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
		
		return jws.getCompactSerialization();
	}

	private String buildKID(X509Certificate cert) {
		StringBuffer b = new StringBuffer();
		b.append(cert.getSubjectDN().getName()).append('-').append(cert.getIssuerDN().getName()).append('-').append(cert.getSerialNumber().toString());
		return b.toString();
	}
	
	public void addUserToGroup(String token,HttpCon con,String userName,String groupName,int approvalID,Workflow workflow) throws Exception {
		Gson gson = new Gson();
		StringBuffer b = new StringBuffer();
		b.append("/apis/user.openshift.io/v1/groups/").append(groupName);
		String json = this.callWS(token, con, b.toString());
		com.tremolosecurity.unison.openshiftv3.model.groups.Group group = gson.fromJson(json, com.tremolosecurity.unison.openshiftv3.model.groups.Group.class);
		if (group.getUsers() == null) {
			group.setUsers(new HashSet<String>());
		}
		if ( ! group.getUsers().contains(userName)) {
			
			group.getUsers().add(userName);
			json = gson.toJson(group);
			json = this.callWSPut(token, con, b.toString(), json);
			Response resp = gson.fromJson(json, Response.class);
			if (resp.getKind().equals("Group")) {
				this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Add,  approvalID, workflow, "group", groupName);
			} else {
				throw new Exception("Could not add group " + groupName + " to " + userName + " - " + resp.getReason());
			}
		}
	}
	
	public void removeUserFromGroup(String token,HttpCon con,String userName,String groupName,int approvalID,Workflow workflow) throws Exception {
		Gson gson = new Gson();
		StringBuffer b = new StringBuffer();
		b.append("/apis/user.openshift.io/v1/groups/").append(groupName);
		String json = this.callWS(token, con, b.toString());
		com.tremolosecurity.unison.openshiftv3.model.groups.Group group = gson.fromJson(json, com.tremolosecurity.unison.openshiftv3.model.groups.Group.class);
		if (group.getUsers() == null) {
			group.setUsers(new HashSet<String>());
		}
		if (group.getUsers().contains(userName)) {
			
			group.getUsers().remove(userName);
			json = gson.toJson(group);
			json = this.callWSPut(token, con, b.toString(), json);
			Response resp = gson.fromJson(json, Response.class);
			if (resp.getKind().equals("Group")) {
				this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Delete,  approvalID, workflow, "group", groupName);
			} else {
				throw new Exception("Could not remove group " + groupName + " to " + userName + " - " + resp.getReason());
			}
		}
	}

	@Override
	public void addGroup(String name, Map<String,String> additionalAttributes,User user, Map<String, Object> request) throws ProvisioningException {
		HttpCon con = null;
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		try {
			String token = this.getAuthToken();
			con = this.createClient();
			
			Gson gson = new Gson();
			
			
			//first lets see if the group exists
			StringBuilder sb = new StringBuilder();
			sb.append("/apis/user.openshift.io/v1/groups/").append(name);

			com.tremolosecurity.unison.openshiftv3.model.groups.Group group = new com.tremolosecurity.unison.openshiftv3.model.groups.Group();
				group.setKind("Group");
				group.setApiVersion("user.openshift.io/v1");
				group.setMetadata(new HashMap<String,Object>());
				group.getMetadata().put("name", name);
				group.getMetadata().put("creationTimestamp", null);
				group.setUsers(null);
				String jsonInput = gson.toJson(group);

			if (! this.isObjectExists(token, con, "/apis/user.openshift.io/v1/groups",jsonInput)) {

				
				String json = this.callWSPost(token, con, "/apis/user.openshift.io/v1/groups", jsonInput);

				Response resp = gson.fromJson(json, Response.class);
				
				
				if (resp.getKind().equalsIgnoreCase("Group")) {
					this.cfgMgr.getProvisioningEngine().logAction(name,true, ActionType.Add,  approvalID, workflow, "group-object", name);
				} else {
					throw new ProvisioningException("Unknown response : '" + json + "'");
				}
			
			}
		} catch (Exception e) {
			throw new ProvisioningException("Could not load group",e);
		} finally {
			if (con != null) {
				con.getBcm().close();
			}
		}
		
	}

	@Override
	public void deleteGroup(String name, User user, Map<String, Object> request) throws ProvisioningException {
		HttpCon con = null;
		
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		
		try {
			String token = this.getAuthToken();
			con = this.createClient();
			
			Gson gson = new Gson();
			StringBuffer b = new StringBuffer();
			b.append("/apis/user.openshift.io/v1/groups/").append(name);
			String json = this.callWSDelete(token, con, b.toString());
			Response resp = gson.fromJson(json, Response.class);
			
			
			if (resp.getStatus().equalsIgnoreCase("Success")) {
				this.cfgMgr.getProvisioningEngine().logAction(name,true, ActionType.Delete,  approvalID, workflow, "group-object", name);
			} else {
				throw new ProvisioningException("Unknown response : '" + json + "'");
			}
		} catch (Exception e) {
			throw new ProvisioningException("Could not load group",e);
		} finally {
			if (con != null) {
				con.getBcm().close();
			}
		}
		
	}

	@Override
	public boolean isGroupExists(String name, User user, Map<String, Object> request) throws ProvisioningException {
		HttpCon con = null;
		
		try {
			String token = this.getAuthToken();
			con = this.createClient();
			
			Gson gson = new Gson();
			StringBuffer b = new StringBuffer();
			b.append("/apis/user.openshift.io/v1/groups/").append(name);
			String json = this.callWS(token, con, b.toString());
			com.tremolosecurity.unison.openshiftv3.model.groups.Group group = gson.fromJson(json, com.tremolosecurity.unison.openshiftv3.model.groups.Group.class);
			
			
			if (group.getStatus() != null && group.getStatus().equalsIgnoreCase("Failure")) {
				return false;
			} else if (group.getKind().equalsIgnoreCase("Group")) {
				return true;
			} else {
				throw new ProvisioningException("Unknown response : '" + json + "'");
			}
		} catch (Exception e) {
			throw new ProvisioningException("Could not load group",e);
		} finally {
			if (con != null) {
				con.getBcm().close();
			}
		}
	}
	
	public static String sub2uid(String sub) {
		StringBuilder uid = new StringBuilder();
		for (Character c : sub.toCharArray()) {
			if (c == '.' || c == '-' || (c >= 'a' && c <= 'z')) {
				uid.append(c);
			} else if (c >= 'A' && c <= 'Z') {
 				uid.append(Character.toLowerCase(c));
 			} else {
 				uid.append("x-").append(String.valueOf((int) c.charValue())).append("-x");
 			}
			
			
		}
		
		
		
		return uid.toString();
		
	}

	public String getUrl() {
		if (this.url.isEmpty()) {
			return new StringBuilder().append("https://").append(System.getenv("KUBERNETES_SERVICE_HOST")).append(":").append(System.getenv("KUBERNETES_SERVICE_PORT")).toString();
		} else {
			return this.url;
		}
		
	}

	@Override
	public void shutdown() throws ProvisioningException {
		
		
	}
	
	
	private  X509Certificate pem2cert(String pem) throws Exception {
        if (!pem.startsWith("-")) {
            pem = new String(java.util.Base64.getDecoder().decode(pem));
        }

        ByteArrayInputStream bais = new ByteArrayInputStream(pem.getBytes("UTF-8"));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Collection<? extends java.security.cert.Certificate> c = cf.generateCertificates(bais);
        return (X509Certificate) c.iterator().next();
    }
	
	public String getLabel() { 
		return this.label;
	}
	
	public String getGitUrl() {
		return this.gitUrl;
	}
	
	public void loadRemoteKeyMaterial(ConfigManager cfgMgr,String uri) throws Exception {
		
		if (cfgMgr.getProvisioningEngine() == null) {
			logger.warn("k8s target not yet available");
			return;
		}
		
		ProvisioningTarget target = cfgMgr.getProvisioningEngine().getTarget("k8s");
		if (target == null) {
			logger.warn("k8s target not yet available");
			return;
		}
		
		OpenShiftTarget k8s = (OpenShiftTarget) target.getProvider();
		HttpCon http = k8s.createClient();
		
		try {
			if (! k8s.isObjectExistsByPath(k8s.getAuthToken(), http, uri)) {
				logger.error("Could not load " + uri + " from the k8s cluster");
			} else {
				String json = k8s.callWS(k8s.getAuthToken(), http, uri);
				JSONObject root =(JSONObject)  new JSONParser().parse(json);
				JSONObject data = (JSONObject) root.get("data");
				String certAuthorityData = (String) data.get("certificate-authority");
				if (certAuthorityData == null) {
					logger.error("Could not load certificate-authority from " + uri);
					return;
				}
				
				
				String clientCert = (String) data.get("client-certificate");
				if (clientCert == null) {
					logger.error("Could not load client-certificate from " + uri);
					return;
				}
				
				String clientKey = (String) data.get("client-key");
				if (clientKey == null) {
					logger.error("Could not load client-key from " + uri);
					return;
				}
				
				
				// add ca cert
				String pem = new String(java.util.Base64.getDecoder().decode(certAuthorityData));
				ByteArrayInputStream bais = new ByteArrayInputStream(pem.getBytes("UTF-8"));
		        CertificateFactory cf = CertificateFactory.getInstance("X.509");
		        Collection<? extends java.security.cert.Certificate> c = cf.generateCertificates(bais);
		        int i = 0;
		        for (java.security.cert.Certificate cert : c) {
		        	cfgMgr.getKeyStore().setCertificateEntry(this.name + "-cacert-" + i, cert);
		        	i++;
		        }
		        
		        // add key
		        pem = new String(java.util.Base64.getDecoder().decode(clientCert));
				bais = new ByteArrayInputStream(pem.getBytes("UTF-8"));
		        cf = CertificateFactory.getInstance("X.509");
		        c = cf.generateCertificates(bais);
		        
		        java.security.cert.Certificate[] certs = new java.security.cert.Certificate[c.size()];
		        i = 0 ;
		        for (java.security.cert.Certificate cert : c) {
		        	certs[i] = cert;
		        	i++;
		        }
		        
		        pem = new String(java.util.Base64.getDecoder().decode(clientKey));
				bais = new ByteArrayInputStream(pem.getBytes("UTF-8"));
				Object parsed = new org.bouncycastle.openssl.PEMParser(new InputStreamReader(bais)).readObject();
			    KeyPair pair = new org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter().getKeyPair((org.bouncycastle.openssl.PEMKeyPair)parsed);
		        
		        cfgMgr.getKeyStore().setKeyEntry(this.name + "-client", pair.getPrivate(), cfgMgr.getCfg().getKeyStorePassword().toCharArray(), certs);
		        
		        
				
			}
		} finally {
			if (http != null) {
				http.getHttp().close();
				http.getBcm().close();
			}
		}
	}

	@Override
	public Map<String, String> getAnnotations() {
		return this.annotations;
	}

	@Override
	public Map<String, String> getLabels() {
		return this.labels;
	}
	
	public String getName() {
		return this.name;
	}
}
