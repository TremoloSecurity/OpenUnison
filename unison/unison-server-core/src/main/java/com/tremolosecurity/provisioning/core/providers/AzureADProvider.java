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
package com.tremolosecurity.provisioning.core.providers;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.message.BasicHeader;
import org.apache.http.util.EntityUtils;
import org.apache.logging.log4j.Logger;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.microsoft.aad.msal4j.ClientCredentialFactory;
import com.microsoft.aad.msal4j.ClientCredentialParameters;
import com.microsoft.aad.msal4j.ConfidentialClientApplication;
import com.microsoft.aad.msal4j.IAuthenticationResult;
import com.microsoft.aad.msal4j.IClientCredential;
import com.microsoft.aad.msal4j.SilentParameters;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.UserStoreProviderWithAddGroup;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.util.GenPasswd;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.saml.Attribute.DataType;

public class AzureADProvider implements UserStoreProviderWithAddGroup {
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(AzureADProvider.class);
	
	static final String[] claims = new String[] {
			"Group.Create",
			"Group.ReadWrite.All",
			"GroupMember.ReadWrite.All",
			"User.Invite.All",
			"User.ManageIdentities.All",
			"User.Read",
			"User.ReadWrite.All"
	};
	
	String clientSecret;
	String clientId = "";
	String tenantId = "";
	Set<String> clientScopes;
	ConfidentialClientApplication app;
	private String authority;
	IAuthenticationResult azureAuthToken;
	

	private ConfigManager cfgMgr;
	
	String name;
	

	@Override
	public void createUser(User user, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		
		
		
		
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		if (request.containsKey("tremolo.azuread.external") && request.get("tremolo.azuread.external").equals("true")) {
			JSONObject root = new JSONObject();
			root.put("invitedUserEmailAddress",user.getAttribs().get("mail").getValues().get(0));
			root.put("inviteRedirectUrl", request.get("tremolo.azuread.invitation.redirect"));
			root.put("sendInvitationMessage", true);
			
			JSONObject invitation = new JSONObject();
			invitation.put("ccRecipients", new JSONArray());
			invitation.put("customizedMessageBody",request.get("tremolo.azuread.invitation.message"));
			
			root.put("invitedUserMessageInfo", invitation);
			
			
			HttpCon con = null;
			try {
				con = this.createClient();
				
				String json = this.callWSPostJsonReesponseExpected(con, "/invitations", root.toString());
				
				root = (JSONObject) new JSONParser().parse(json);
				
				
				String id = ((JSONObject)root.get("invitedUser")).get("id").toString();
				String userPrincipalName = this.getUpnFromId(con, id);
				
				if (userPrincipalName == null) {
					throw new ProvisioningException("user not created");
				}
						
				user.setUserID(userPrincipalName);
				user.getAttribs().put("userPrincipalName", new Attribute("userPrincipalName",userPrincipalName));
				user.getAttribs().put("id", new Attribute("id",id));
				
				
				this.cfgMgr.getProvisioningEngine().logAction(this.name,true, ActionType.Add,  approvalID, workflow, "userPrincipalName", user.getAttribs().get("userPrincipalName").getValues().get(0));
				this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Add,  approvalID, workflow, "userPrincipalName", user.getAttribs().get("userPrincipalName").getValues().get(0));
				
				User fromAzure = this.findUser(userPrincipalName, attributes, request);
				
				int i = 0;
				while (fromAzure == null) {
					if (i > 10) {
						throw new ProvisioningException("New user not available");
					}
					Thread.sleep(1000);
					try {
					fromAzure = this.findUser(userPrincipalName, attributes, request);
					
					} catch (ProvisioningException e) {
						//do notthing
					}
					i++;
				}
				
				
				this.synUser(user, true, attributes, fromAzure, approvalID, workflow);
				
			} catch (Exception e) {
				throw new ProvisioningException("Could not create invitd user",e);
			} finally {
				try {
					con.getHttp().close();
				} catch (IOException e) {
					
				}
				con.getBcm().close();
			}
			
		} else {
			createInternalUser(user, attributes, request, approvalID, workflow);
		}
		
		

	}

	private void createInternalUser(User user, Set<String> attributes, Map<String, Object> request, int approvalID,
			Workflow workflow) throws ProvisioningException {
		JSONObject root = new JSONObject();
		if (user.getAttribs().get("accountEnabled") != null) {
			root.put("accountEnabled", user.getAttribs().get("accountEnabled").getValues().get(0).equalsIgnoreCase("true"));
		}
		
		root.put("displayName", user.getAttribs().get("displayName").getValues().get(0));
		
		
		if (user.getAttribs().get("onPremisesImmutableId") != null) {
			root.put("onPremisesImmutableId", user.getAttribs().get("onPremisesImmutableId").getValues().get(0));
		}
		String mail;
		
		if (user.getAttribs().get("mail") != null) {
			mail = user.getAttribs().get("mail").getValues().get(0);
		} else {
			mail = user.getAttribs().get("userPrincipalName").getValues().get(0);
		}
		
		String mailNickName = mail.substring(0,mail.indexOf('@'));
		
		root.put("mailNickname", mailNickName);
		
		root.put("userPrincipalName", user.getAttribs().get("userPrincipalName").getValues().get(0));
		
		JSONObject passwordPolicy = new JSONObject();
		
		if (user.getPassword() != null && ! user.getPassword().isEmpty()) {
			passwordPolicy.put("password", user.getPassword());
		} else {
			passwordPolicy.put("password", new GenPasswd(50,true,true,true,true).getPassword());
		}
		
		passwordPolicy.put("forceChangePasswordNextSignIn", request.get("tremolo.azuread.create.forceChangePasswordNextSignIn") != null && request.get("tremolo.azuread.create.forceChangePasswordNextSignIn").equals("true"));
		passwordPolicy.put("forceChangePasswordNextSignInWithMfa", request.get("tremolo.azuread.create.forceChangePasswordNextSignInWithMfa") != null && request.get("tremolo.azuread.create.forceChangePasswordNextSignInWithMfa").equals("true"));
		root.put("passwordProfile", passwordPolicy);
		
		HttpCon con = null;
		try {
			con = this.createClient();
			
			String json = this.callWSPostJsonReesponseExpected(con, "/users", root.toString());
			
			JSONObject resp = (JSONObject) new JSONParser().parse(json);
			
			user.getAttribs().put("id", new Attribute("id",(String) resp.get("id")));
			
			
			this.cfgMgr.getProvisioningEngine().logAction(this.name,true, ActionType.Add,  approvalID, workflow, "userPrincipalName", user.getAttribs().get("userPrincipalName").getValues().get(0));
			this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Add,  approvalID, workflow, "userPrincipalName", user.getAttribs().get("userPrincipalName").getValues().get(0));
			this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Add,  approvalID, workflow, "password", "*********8");
			
			if (user.getAttribs().get("accountEnabled") != null) {
				
				this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Add,  approvalID, workflow, "accountEnabled", user.getAttribs().get("accountEnabled").getValues().get(0));
			}
			
			if (user.getAttribs().get("onPremisesImmutableId") != null) {
				
				this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Add,  approvalID, workflow, "onPremisesImmutableId", user.getAttribs().get("onPremisesImmutableId").getValues().get(0));
			}
			
			User fromAzure = new User(user.getUserID());
			
			
			fromAzure.getAttribs().put("id", new Attribute("id",user.getAttribs().get("id").getValues().get(0)));
			fromAzure.getAttribs().put("userPrincipalName", new Attribute("displayName",user.getAttribs().get("userPrincipalName").getValues().get(0)));
			
			this.synUser(user, true, attributes, fromAzure, approvalID, workflow);
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not create user",e);
		} finally {
			try {
				con.getHttp().close();
			} catch (IOException e) {
				
			}
			con.getBcm().close();
		}
	}

	@Override
	public void setUserPassword(User user, Map<String, Object> request) throws ProvisioningException {
		// TODO Auto-generated method stub

	}

	@Override
	public void syncUser(User user, boolean addOnly, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		
		
		User fromAzure = this.findUser(user.getUserID(), attributes, request);
		
		if (fromAzure == null) {
			this.createUser(user, attributes, request);
			return;
		}
		
		
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		
		
		
		
		synUser(user, addOnly, attributes, fromAzure, approvalID, workflow);
		
		
		

	}

	private void synUser(User user, boolean addOnly, Set<String> attributes, User fromAzure, int approvalID,
			Workflow workflow) throws ProvisioningException {
		List<AttributeChange> changes = new ArrayList<AttributeChange>();
		JSONObject patch = new JSONObject();
		for (String attributeName : attributes) {
			 
			if (attributeName.equals("mail") || attributeName.equals("id")) {
				continue;
			}
			
			Attribute fromUser = user.getAttribs().get(attributeName);
			Attribute fromAd = fromAzure.getAttribs().get(attributeName);
			
			if (fromUser != null && fromAd == null) {
				patch.put(attributeName,getValue(fromUser));
				changes.add(new AttributeChange(fromUser.getName(),fromUser.getValues().get(0),ActionType.Add));
			} else if (fromUser != null && fromAd != null && ! (fromUser.getValues().get(0).equals(fromAd.getValues().get(0)))) {
				patch.put(attributeName,getValue(fromUser));
				changes.add(new AttributeChange(fromUser.getName(),fromUser.getValues().get(0),ActionType.Replace));
			} else if (fromUser == null && fromAd != null && ! addOnly) {
				patch.put(attributeName,null);
				changes.add(new AttributeChange(fromAd.getName(),fromAd.getValues().get(0),ActionType.Delete));
			}
		}
		
		
		String id;
		
		if (fromAzure.getAttribs().get("id") != null) {
			id = fromAzure.getAttribs().get("id").getValues().get(0);
		} else {
			id = user.getAttribs().get("id").getValues().get(0);
		}
		
		HttpCon con = null;
		try {
			con = this.createClient();
			StringBuilder sb = new StringBuilder();
			this.callWSPatchJson(con, sb.append("/users/").append(URLEncoder.encode(user.getUserID(), "UTf-8")).toString(), patch.toString());
			
			for (AttributeChange change : changes) {
				this.cfgMgr.getProvisioningEngine().logAction(this.name,false, change.action,  approvalID, workflow, change.name, change.value);
			}
			
			Map<String,String> groups = this.loadGroups(con);
			
			Set<String> curentGroups = new HashSet<String>();
			curentGroups.addAll(fromAzure.getGroups());
			for (String group : user.getGroups()) {
				if (! curentGroups.contains(group)) {
					String uri = new StringBuilder().append("/groups/").append(groups.get(group)).append("/members/$ref").toString();
					JSONObject root = new JSONObject();
					root.put("@odata.id", new StringBuilder().append("https://graph.microsoft.com/v1.0/directoryObjects/").append(id).toString()  );
					this.callWSPostJsonNoReesponseExpected(con, uri, root.toString());
					this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Add,  approvalID, workflow, "group", group);
				}
			}
			
			if (! addOnly) {
				curentGroups = new HashSet<String>();
				curentGroups.addAll(user.getGroups());
				for (String group : fromAzure.getGroups()) {
					if (! curentGroups.contains(group)) {
						String uri = new StringBuilder().append("/groups/").append(groups.get(group)).append("/members/").append(id).append("/$ref").toString();
						
						this.callWSDelete(con, uri);
						this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Delete,  approvalID, workflow, "group", group);
					}
				}
			}
		} catch (Exception e) {
			throw new ProvisioningException("Could not find user",e);
		} finally {
			try {
				con.getHttp().close();
			} catch (IOException e) {
				
			}
			con.getBcm().close();
		}
	}
	
	
	private Map<String,String> loadGroups(HttpCon con) throws ClientProtocolException, IOException, ParseException {
		HashMap<String,String> groups = new HashMap<String,String>();
		
		String json = this.callWS(con, "/groups?$select=displayName,id");
		
		JSONObject root = (JSONObject) new JSONParser().parse(json);
		JSONArray value = (JSONArray) root.get("value");
		for (Object o : value) {
			JSONObject group = (JSONObject) o;
			String id = (String) group.get("id");
			String name = (String) group.get("displayName");
			groups.put(name, id);
		}
		
		return groups;
	}
	
	private Object getValue(Attribute attr) {
		switch (attr.getDataType()) {
			case booleanVal : return Boolean.parseBoolean(attr.getValues().get(0));
			case intNum:
			case longNum: return Long.parseLong(attr.getValues().get(0));
			default: return attr.getValues().get(0);
		}
	}

	@Override
	public void deleteUser(User user, Map<String, Object> request) throws ProvisioningException {
		HttpCon con = null;
		
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		try {
			con = this.createClient();
			this.callDelete(con, new StringBuilder().append("/users/").append(URLEncoder.encode(user.getUserID(), "UTf-8")).toString()  );
			this.cfgMgr.getProvisioningEngine().logAction(this.name,true, ActionType.Delete,  approvalID, workflow, "userPrincipalName", user.getUserID());
		} catch (Exception e) {
			throw new ProvisioningException("Could not delete user",e);
		} finally {
			try {
				con.getHttp().close();
			} catch (IOException e) {
				
			}
			con.getBcm().close();
		}

	}
	
	private String getUpnFromId(HttpCon con,String id) throws ClientProtocolException, UnsupportedEncodingException, IOException, ParseException, ProvisioningException {
		String json = this.callWS(con, new StringBuilder().append("/users/").append(URLEncoder.encode(id, "UTf-8")).toString()  );
		
		
		JSONObject root = (JSONObject) new JSONParser().parse(json);
		
		if (root.containsKey("error") ) {
			JSONObject error = (JSONObject) root.get("error");
			String code = (String) error.get("code");
			if (code.equalsIgnoreCase("Request_ResourceNotFound")) {
				return null;
			} else {
				throw new ProvisioningException("Could not lookup user " + json);
			}
		} else {
			return root.get("userPrincipalName").toString();
		}
	}

	@Override
	public User findUser(String userID, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		HttpCon con = null;
		
		Set<String> attributesLocal = new HashSet<String>();
		attributesLocal.addAll(attributes);
		attributes = attributesLocal;
		
		if (! attributes.contains("id")) {
			attributes.add("id");
		}
		
		StringBuilder select = new StringBuilder();
		for (String attr : attributes) {
			select.append(attr).append(',');
		}
		
		String selectAttrs = select.toString();
		selectAttrs.subSequence(0, selectAttrs.lastIndexOf(','));
		
		try {
			con = this.createClient();
			String json = this.callWS(con, new StringBuilder().append("/users/").append(URLEncoder.encode(userID, "UTf-8")).append("?$select=").append(URLEncoder.encode(selectAttrs, "UTF-8")).toString() );
			
			
			JSONObject root = (JSONObject) new JSONParser().parse(json);
			
			if (root.containsKey("error") ) {
				JSONObject error = (JSONObject) root.get("error");
				String code = (String) error.get("code");
				if (code.equalsIgnoreCase("Request_ResourceNotFound")) {
					return null;
				} else {
					throw new ProvisioningException("Could not lookup user " + json);
				}
			}
			User user = new User((String) root.get("userPrincipalName"));
			
			for (String attributeName : attributes) {
				if (root.get(attributeName) != null) {
					String val = root.get(attributeName).toString();
					user.getAttribs().put(attributeName, new Attribute(attributeName,val));
				}
			}
			
			json = this.callWS(con, new StringBuilder().append("/users/").append(URLEncoder.encode(userID, "UTf-8")).append("/memberOf").toString());
			root = (JSONObject) new JSONParser().parse(json);
			
			if (root.containsKey("error") ) {
				JSONObject error = (JSONObject) root.get("error");
				String code = (String) error.get("code");
				throw new ProvisioningException("Could not lookup user " + json);
				
			}
			
			JSONArray values = (JSONArray) root.get("value");
			
			
			
			for (Object o : values) {
				JSONObject group = (JSONObject) o;
				if (group.get("@odata.type").equals("#microsoft.graph.group")) {
					user.getGroups().add((String)group.get("displayName")); 
				}
				
			}
			
			return user;
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not find user",e);
		} finally {
			try {
				con.getHttp().close();
			} catch (IOException e) {
				
			}
			con.getBcm().close();
		}
		//return null;
	}
	
	

	@Override
	public void init(Map<String, Attribute> cfg, ConfigManager cfgMgr, String name) throws ProvisioningException {
		
		this.name = name;
		
		this.clientId = cfg.get("clientId").getValues().get(0);
		this.tenantId = cfg.get("tenantId").getValues().get(0);
		this.clientSecret = cfg.get("clientSecret").getValues().get(0);
		this.authority = "https://login.microsoftonline.com/" + this.tenantId + "/";
		this.clientScopes = Collections.singleton("https://graph.microsoft.com/.default");
		
		IClientCredential c;
		
		try {
			app = ConfidentialClientApplication.builder(clientId, ClientCredentialFactory.createFromSecret(this.clientSecret)).authority(this.authority).build();
		} catch (MalformedURLException e) {
			throw new ProvisioningException("Could not obtain confidential client application",e);
		}
		

		ClientCredentialParameters parameters =
                ClientCredentialParameters
                        .builder(this.clientScopes)
                        .build();
		
		
		azureAuthToken = app.acquireToken(parameters).join();
		
		
		this.cfgMgr = cfgMgr;

	}

	@Override
	public void addGroup(String name, Map<String, String> additionalAttributes, User user, Map<String, Object> request)
			throws ProvisioningException {
		// TODO Auto-generated method stub

	}

	@Override
	public void deleteGroup(String name, User user, Map<String, Object> request) throws ProvisioningException {
		// TODO Auto-generated method stub

	}

	@Override
	public boolean isGroupExists(String name, User user, Map<String, Object> request) throws ProvisioningException {
		// TODO Auto-generated method stub
		return false;
	}

	public HttpCon createClient() throws Exception {
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
	
	public String getIdFromEmail(String email) throws ProvisioningException {
		HttpCon con = null;
		try {
			con = this.createClient();
			String json = this.callWS(con, new StringBuilder().append("/users?$filter=").append(URLEncoder.encode(new StringBuilder().append("mail eq '").append(email).append( "'").toString() , "UTf-8")).toString());
			
			JSONObject root = (JSONObject) new JSONParser().parse(json);
			
			JSONArray vals = (JSONArray) root.get("value");
			
			if (vals.size() == 0) { 
				return null;
			} else if (vals.size() > 1) {
				throw new ProvisioningException("Multiple entries for " + email);
			} else {
				return ((JSONObject) vals.get(0)).get("userPrincipalName").toString();
			}
			
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not find user",e);
		} finally {
			try {
				con.getHttp().close();
			} catch (IOException e) {
				
			}
			con.getBcm().close();
		}
	}
	
	public String callWS(HttpCon con,String uri) throws IOException, ClientProtocolException {
		StringBuffer b = new StringBuffer();
		
		b.append("https://graph.microsoft.com/v1.0").append(uri);
		HttpGet get = new HttpGet(b.toString());
		b.setLength(0);
		b.append("Bearer ").append(this.azureAuthToken.accessToken());
		get.addHeader(new BasicHeader("Authorization",b.toString()));
		HttpResponse resp = con.getHttp().execute(get);
		
		String json = EntityUtils.toString(resp.getEntity());
		
		if (logger.isDebugEnabled()) {
			logger.debug("url : '" + uri + "'");
			logger.debug("Response Code : " + resp.getStatusLine().getStatusCode());
			logger.debug(json);
		}
		
		return json;
	}
	
	public void callDelete(HttpCon con,String uri) throws IOException, ClientProtocolException {
		StringBuffer b = new StringBuffer();
		
		b.append("https://graph.microsoft.com/v1.0").append(uri);
		HttpDelete get = new HttpDelete(b.toString());
		b.setLength(0);
		b.append("Bearer ").append(this.azureAuthToken.accessToken());
		get.addHeader(new BasicHeader("Authorization",b.toString()));
		HttpResponse resp = con.getHttp().execute(get);
		
		if (resp.getStatusLine().getStatusCode() != 204) {
			throw new IOException("Patch failed " + EntityUtils.toString(resp.getEntity()));
		}
	}
	
	public void callWSPatchJson(HttpCon con,String uri,String json) throws IOException, ClientProtocolException {
		StringBuffer b = new StringBuffer();
		
		b.append("https://graph.microsoft.com/v1.0").append(uri);
		HttpPatch put = new HttpPatch(b.toString());
		b.setLength(0);
		b.append("Bearer ").append(this.azureAuthToken.accessToken());
		put.addHeader(new BasicHeader("Authorization",b.toString()));
		
		StringEntity str = new StringEntity(json,ContentType.create("application/json"));
		put.setEntity(str);
		
		HttpResponse resp = con.getHttp().execute(put);
		
		if (resp.getStatusLine().getStatusCode() != 204) {
			throw new IOException("Patch failed " + EntityUtils.toString(resp.getEntity()));
		}
		
		
	}
	
	public void callWSPostJsonNoReesponseExpected(HttpCon con,String uri,String json) throws IOException, ClientProtocolException {
		StringBuffer b = new StringBuffer();
		
		b.append("https://graph.microsoft.com/v1.0").append(uri);
		HttpPost put = new HttpPost(b.toString());
		b.setLength(0);
		b.append("Bearer ").append(this.azureAuthToken.accessToken());
		put.addHeader(new BasicHeader("Authorization",b.toString()));
		
		StringEntity str = new StringEntity(json,ContentType.create("application/json"));
		put.setEntity(str);
		
		HttpResponse resp = con.getHttp().execute(put);
		
		if (resp.getStatusLine().getStatusCode() != 204) {
			throw new IOException("Post failed " + EntityUtils.toString(resp.getEntity()));
		}
		
		
	}
	
	public String callWSPostJsonReesponseExpected(HttpCon con,String uri,String json) throws IOException, ClientProtocolException {
		StringBuffer b = new StringBuffer();
		
		b.append("https://graph.microsoft.com/v1.0").append(uri);
		HttpPost put = new HttpPost(b.toString());
		b.setLength(0);
		b.append("Bearer ").append(this.azureAuthToken.accessToken());
		put.addHeader(new BasicHeader("Authorization",b.toString()));
		
		StringEntity str = new StringEntity(json,ContentType.create("application/json"));
		put.setEntity(str);
		
		HttpResponse resp = con.getHttp().execute(put);
		
		if (resp.getStatusLine().getStatusCode() != 201) {
			throw new IOException("Post failed " + EntityUtils.toString(resp.getEntity()));
		} else {
			return EntityUtils.toString(resp.getEntity());
		}
		
		
	}
	
	public void callWSDelete(HttpCon con,String uri) throws IOException, ClientProtocolException {
		StringBuffer b = new StringBuffer();
		
		b.append("https://graph.microsoft.com/v1.0").append(uri);
		HttpDelete put = new HttpDelete(b.toString());
		b.setLength(0);
		b.append("Bearer ").append(this.azureAuthToken.accessToken());
		put.addHeader(new BasicHeader("Authorization",b.toString()));
		
		
		
		HttpResponse resp = con.getHttp().execute(put);
		
		if (resp.getStatusLine().getStatusCode() != 204) {
			throw new IOException("Delete failed " + EntityUtils.toString(resp.getEntity()));
		}
		
		
	}
}

class AttributeChange {
	String name;
	String value;
	ActionType action;
	
	public AttributeChange(String name,String value,ActionType action) {
		this.name = name;
		this.value = value;
		this.action = action;
	}
}
