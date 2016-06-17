/*******************************************************************************
 * Copyright 2015 Tremolo Security, Inc.
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
package com.tremolosecurity.unison.freeipa;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.apache.logging.log4j.Logger;

import com.google.gson.Gson;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.UserStoreProvider;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.proxy.myvd.inserts.admin.PBKDF2;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.unison.freeipa.json.IPACall;
import com.tremolosecurity.unison.freeipa.json.IPAResponse;
import com.tremolosecurity.unison.freeipa.util.IPAException;




public class FreeIPATarget implements UserStoreProvider{

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(FreeIPATarget.class.getName());
	
	SecureRandom random;
	
	String url;
	String userName;
	String password;
	boolean createShadowAccount;
	
	private ConfigManager cfgMgr;

	private String name;
	
	
	private void addGroup(String userID, String groupName,
			HttpCon con, int approvalID, Workflow workflow) throws Exception {
		
		
		IPACall addGroup = new IPACall();
		addGroup.setId(0);
		addGroup.setMethod("group_add_member");
		ArrayList<String> groupNames = new ArrayList<String>();
		groupNames.add(groupName);
		
		addGroup.getParams().add(groupNames);
		
		
		HashMap<String,Object> nvps = new HashMap<String,Object>();
		ArrayList<String> users = new ArrayList<String>();
		users.add(userID);
		nvps.put("user", users);
		
		addGroup.getParams().add(nvps);
		
		IPAResponse resp = this.executeIPACall(addGroup, con);
		
		this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Add,  approvalID, workflow, "group", groupName);
		
	}
	
	private void removeGroup(String userID, String groupName,
			HttpCon con, int approvalID, Workflow workflow) throws Exception {
		
		IPACall addGroup = new IPACall();
		addGroup.setId(0);
		addGroup.setMethod("group_remove_member");
		
		ArrayList<String> groupNames = new ArrayList<String>();
		groupNames.add(groupName);
		
		addGroup.getParams().add(groupNames);
		
		
		HashMap<String,Object> nvps = new HashMap<String,Object>();
		ArrayList<String> users = new ArrayList<String>();
		users.add(userID);
		nvps.put("user", users);
		
		addGroup.getParams().add(nvps);
		
		IPAResponse resp = this.executeIPACall(addGroup, con);
		
		this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Delete,  approvalID, workflow, "group", groupName);
		
	}
	
	
	public void createUser(User user, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		try {
			HttpCon con = this.createClient();
			
			try {
				IPACall createUser = new IPACall();
				createUser.setId(0);
				createUser.setMethod("user_add");
				
				ArrayList<String> userArray = new ArrayList<String>();
				userArray.add(user.getUserID());
				createUser.getParams().add(userArray);
				
				HashMap<String,Object> userAttrs = new HashMap<String,Object>();
				
				for (String attrName : attributes) {
					Attribute attr = user.getAttribs().get(attrName);
					
					if (attr != null && ! attr.getName().equalsIgnoreCase("uid")) {
						if (attr.getValues().size() == 1) {
							userAttrs.put(attr.getName(), attr.getValues().get(0));
						} else {
							ArrayList vals = new ArrayList<String>();
							vals.addAll(attr.getValues());
							userAttrs.put(attr.getName(), vals);
						}
						
						
					}
				}
				
				createUser.getParams().add(userAttrs);
				
				IPAResponse resp = this.executeIPACall(createUser, con);
				
				this.cfgMgr.getProvisioningEngine().logAction(name,true, ActionType.Add,  approvalID, workflow, "uid", user.getUserID());
				this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Add,  approvalID, workflow, "uid", user.getUserID());
				
				for (String attrName : userAttrs.keySet()) {
					Object o = userAttrs.get(attrName);
					if (o instanceof String) {
						this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Add,  approvalID, workflow, attrName, (String) o);
					} else {
						List<String> vals = (List<String>) o;
						for (String val : vals) {
							this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Add,  approvalID, workflow, attrName, val);
						}
					}
				}
				
				
				
				for (String group : user.getGroups()) {
					this.addGroup(user.getUserID(), group, con, approvalID, workflow);
				}
				
				if (this.createShadowAccount) {
					String password = new BigInteger(130, random).toString(32);
					password = PBKDF2.generateHash(password);
					user.setPassword(password);
					this.setUserPassword(user, request);
				}
				
			} finally {
				if (con != null) {
					con.getBcm().shutdown();
				}
			}
		} catch (Exception e) {
			throw new ProvisioningException("Could not run search",e);
		}
		
	}

	public void deleteUser(User user, Map<String, Object> request)
			throws ProvisioningException {
		
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		try {
			HttpCon con = this.createClient();
			
			try {
				IPACall deleteUser = new IPACall();
				deleteUser.setId(0);
				deleteUser.setMethod("user_del");
				
				ArrayList<String> userArray = new ArrayList<String>();
				userArray.add(user.getUserID());
				deleteUser.getParams().add(userArray);
				
				HashMap<String,String> additionalParams = new HashMap<String,String>();
				
				deleteUser.getParams().add(additionalParams);
				
				IPAResponse resp = this.executeIPACall(deleteUser, con);
				
				this.cfgMgr.getProvisioningEngine().logAction(name,true, ActionType.Delete,  approvalID, workflow, "uid", user.getUserID());
			} finally {
				if (con != null) {
					con.getBcm().shutdown();
				}
			}
		} catch (Exception e) {
			throw new ProvisioningException("Could not run search",e);
		}
		
	}

	public User findUser(String userID, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		try {
			HttpCon con = this.createClient();
			
			try {
				return findUser(userID, attributes, con);
				
			} finally {
				if (con != null) {
					con.getBcm().shutdown();
				}
			}
		} catch (IPAException e) {
			throw e;
		} catch (Exception e) {
			throw new ProvisioningException("Could not run search",e);
		}
		
	}

	private User findUser(String userID, Set<String> attributes, HttpCon con)
			throws IPAException, ClientProtocolException, IOException {
		IPACall userSearch = new IPACall();
		userSearch.setId(0);
		userSearch.setMethod("user_show");
		
		ArrayList<String> userArray = new ArrayList<String>();
		userArray.add(userID);
		userSearch.getParams().add(userArray);
		
		HashMap<String,String> additionalParams = new HashMap<String,String>();
		additionalParams.put("all", "true");
		additionalParams.put("rights", "true");
		userSearch.getParams().add(additionalParams);
		
		IPAResponse resp = this.executeIPACall(userSearch, con);
		
		User user = new User();
		user.setUserID(userID);
		Map<String,Object> results = (Map<String,Object>) resp.getResult().getResult();
		
		for (String attributeName : attributes) {
			
			if (results.get(attributeName) != null) {
				if (results.get(attributeName) instanceof List) {
					Attribute a = user.getAttribs().get(attributeName);
					if (a == null) {
						a = new Attribute(attributeName);
						user.getAttribs().put(attributeName, a);
					}
					List l = (List) results.get(attributeName);
					for (Object o : l) {
						a.getValues().add((String) o);
					}
				} else {
					Attribute a = user.getAttribs().get(attributeName);
					if (a == null) {
						a = new Attribute(attributeName);
						user.getAttribs().put(attributeName, a);
					}
					a.getValues().add((String) results.get(attributeName));
				}
			}
		}
		
		if (results != null && results.get("memberof_group") != null) {
			for (Object o : ((List) results.get("memberof_group"))) {
				String groupName = (String) o;
				user.getGroups().add(groupName);
			}
		}
		return user;
	}
	
	private IPAResponse executeIPACall(IPACall ipaCall,HttpCon con) throws IPAException, ClientProtocolException, IOException {
		
		Gson gson = new Gson();
		String json = gson.toJson(ipaCall);
		
		if (logger.isDebugEnabled()) {
			logger.debug("Outbound JSON : '" + json + "'");
		}
		
		HttpClient http = con.getHttp();
		
		StringEntity str = new StringEntity(json,ContentType.APPLICATION_JSON);
		HttpPost httppost = new HttpPost(this.url + "/ipa/session/json");
		httppost.addHeader("Referer", this.url + "/ipa/ui/");
		httppost.setEntity(str);
		HttpResponse resp = http.execute(httppost);
		
		
		
		
		
		
		BufferedReader in = new BufferedReader(new InputStreamReader(resp.getEntity().getContent()));
		StringBuffer b = new StringBuffer();
		String line = null;
		while ((line = in.readLine()) != null) {
			b.append(line);
		}
		
		if (logger.isDebugEnabled()) {
			logger.info("Inbound JSON : " + b.toString());
		}
		
		EntityUtils.consumeQuietly(resp.getEntity());
		httppost.completed();
		
		IPAResponse ipaResponse = gson.fromJson(b.toString(), IPAResponse.class);
		
		if (ipaResponse.getError() != null) {
			IPAException ipaException = new IPAException(ipaResponse.getError().getMessage());
			ipaException.setCode(ipaResponse.getError().getCode());
			ipaException.setName(ipaResponse.getError().getName());
			throw ipaException;
		} else {
			return ipaResponse;
		}
		
	}

	public void init(Map<String, Attribute> cfg, ConfigManager cfgMgr,
			String name) throws ProvisioningException {
		this.url = this.loadOption("url", cfg, false);
		this.userName = this.loadOption("userName", cfg, false);
		this.password = this.loadOption("password", cfg, true);
		this.createShadowAccount = Boolean.parseBoolean(this.loadOption("createShadowAccounts", cfg, false));
		this.cfgMgr = cfgMgr;
		this.name = name;
		
		this.random = new SecureRandom();
		
		
	}
	
	private String loadOption(String name,Map<String,Attribute> cfg,boolean mask) throws ProvisioningException{
		if (! cfg.containsKey(name)) {
			throw new ProvisioningException(name + " is required");
		} else {
			String val = cfg.get(name).getValues().get(0); 
			if (! mask) {
				logger.info("Config " + name + "='" + val + "'");
			} else {
				logger.info("Config " + name + "='*****'");
			}
			
			return val;
		}
	}
	
	private HttpCon createClient() throws Exception {
		return this.createClient(this.userName, this.password);
	}
	
	private HttpCon createClient(String lusername,String lpassword) throws Exception {
		
		BasicHttpClientConnectionManager bhcm = new BasicHttpClientConnectionManager(cfgMgr.getHttpClientSocketRegistry());
		
		
		RequestConfig rc = RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD).build();
		
		    CloseableHttpClient http = HttpClients.custom().setConnectionManager(bhcm).setDefaultRequestConfig(rc).build();
		    
		    http.execute(new HttpGet(this.url + "/ipa/session/login_kerberos")).close();
		    
		    
		doLogin(lusername, lpassword, http);
		
		HttpCon con = new HttpCon();
		con.setBcm(bhcm);
		con.setHttp(http);
		
		return con;
		
	}

	private void doLogin(String lusername, String lpassword,
			CloseableHttpClient http) throws UnsupportedEncodingException,
			IOException, ClientProtocolException {
		HttpPost httppost = new HttpPost(this.url + "/ipa/session/login_password");
		
		List<NameValuePair> formparams = new ArrayList<NameValuePair>();
		formparams.add(new BasicNameValuePair("user", lusername));
		formparams.add(new BasicNameValuePair("password", lpassword));
		UrlEncodedFormEntity entity = new UrlEncodedFormEntity(formparams, "UTF-8");

		
		httppost.setEntity(entity);
		
		CloseableHttpResponse response = http.execute(httppost);
		if (logger.isDebugEnabled()) {
			logger.debug("Login response : " + response.getStatusLine().getStatusCode());
		}
		
		response.close();
	}

	public void setUserPassword(User user, Map<String, Object> request)
			throws ProvisioningException {
		
		if (user.getPassword() != null && ! user.getPassword().isEmpty()) {
			int approvalID = 0;
			if (request.containsKey("APPROVAL_ID")) {
				approvalID = (Integer) request.get("APPROVAL_ID");
			}
			
			Workflow workflow = (Workflow) request.get("WORKFLOW");
			
			try {
				HttpCon con = this.createClient();
				
				try {
					IPACall setPassword = new IPACall();
					setPassword.setId(0);
					setPassword.setMethod("passwd");
					
					ArrayList<String> userArray = new ArrayList<String>();
					userArray.add(user.getUserID());
					setPassword.getParams().add(userArray);
					
					HashMap<String,String> additionalParams = new HashMap<String,String>();
					additionalParams.put("password", user.getPassword());
					setPassword.getParams().add(additionalParams);
					
					IPAResponse resp = this.executeIPACall(setPassword, con);
					con.getBcm().shutdown();
					
					//no we need to reset the password, this is a hack.  right way is to tell IPA the user doesn't need to reset their password
					HttpPost httppost = new HttpPost(this.url + "/ipa/session/change_password");
					httppost.addHeader("Referer", this.url + "/ipa/ui/");	
					List<NameValuePair> formparams = new ArrayList<NameValuePair>();
					formparams.add(new BasicNameValuePair("user", user.getUserID()));
					formparams.add(new BasicNameValuePair("old_password", user.getPassword()));
					formparams.add(new BasicNameValuePair("new_password", user.getPassword()));
					UrlEncodedFormEntity entity = new UrlEncodedFormEntity(formparams, "UTF-8");
	
					
					httppost.setEntity(entity);
					
					
					
					con = this.createClient(user.getUserID(), user.getPassword());
					CloseableHttpClient http = con.getHttp();
					 
					
					CloseableHttpResponse httpResp = http.execute(httppost);
					
					if (logger.isDebugEnabled()) {
						logger.debug("Response of password reset : " + httpResp.getStatusLine().getStatusCode());
					}
					
					
					this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Replace,  approvalID, workflow, "userPassword", "********************************");
				} finally {
					if (con != null) {
						con.getBcm().shutdown();
					}
				}
			} catch (Exception e) {
				throw new ProvisioningException("Could not run search",e);
			}
		}
		
	}
	
	
	private void setAttribute(String userID, Attribute attrNew,
			HttpCon con, int approvalID, Workflow workflow) throws Exception {
		
		IPACall modify = new IPACall();
		modify.setId(0);
		modify.setMethod("user_mod");
		
		ArrayList<String> userArray = new ArrayList<String>();
		userArray.add(userID);
		modify.getParams().add(userArray);
		
		HashMap<String,Object> additionalParams = new HashMap<String,Object>();
		if (attrNew.getValues().size() > 1) {
			additionalParams.put(attrNew.getName(), attrNew.getValues());
		} else {
			additionalParams.put(attrNew.getName(), attrNew.getValues().get(0));
		}
		
		modify.getParams().add(additionalParams);
		
		IPAResponse resp = this.executeIPACall(modify, con);
	}
	
	private void deleteAttribute(String userID, String attrName,
			HttpCon con, int approvalID, Workflow workflow) throws Exception {
		
		IPACall modify = new IPACall();
		modify.setId(0);
		modify.setMethod("user_mod");
		
		ArrayList<String> userArray = new ArrayList<String>();
		userArray.add(userID);
		modify.getParams().add(userArray);
		
		HashMap<String,Object> additionalParams = new HashMap<String,Object>();
		additionalParams.put(attrName, "");
		
		
		modify.getParams().add(additionalParams);
		
		IPAResponse resp = this.executeIPACall(modify, con);
	}
	
	
	

	public void syncUser(User user, boolean addOnly, Set<String> attributes,
			Map<String, Object> request) throws ProvisioningException {
		
		
		
		User fromIPA = null;
		HttpCon con = null;
		try {
		con = this.createClient();
		
			try {
				fromIPA = this.findUser(user.getUserID(), attributes, request); 
			} catch (IPAException ipaException) {
				if (ipaException.getCode() != 4001) {
					throw ipaException;
				}
			}
			
			
			
			int approvalID = 0;
			if (request.containsKey("APPROVAL_ID")) {
				approvalID = (Integer) request.get("APPROVAL_ID");
			}
			
			Workflow workflow = (Workflow) request.get("WORKFLOW");
			
			if (fromIPA == null) {
				this.createUser(user, attributes, request);
			} else {
				//check to see if the attributes from the incoming object match
				for (String attrName : attributes) {
					if (attrName.equalsIgnoreCase("uid")) {
						continue;
					}
					
					Attribute attrNew = checkAttribute(user, fromIPA, con,
							approvalID, workflow, attrName, addOnly);
					
				}
				
				if (! addOnly) {
					for (String attrToDel : fromIPA.getAttribs().keySet()) {
						if (! attrToDel.equalsIgnoreCase("uid")) {
							//These attributes were no longer on the user, delete them
							this.deleteAttribute(user.getUserID(), attrToDel, con, approvalID, workflow);
							this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Delete,  approvalID, workflow, attrToDel, "");
						}
					}
				}
				
				//check groups
				HashSet<String> curGroups = new HashSet<String>();
				curGroups.addAll(fromIPA.getGroups());
				for (String group : user.getGroups()) {
					if (curGroups.contains(group)) {
						curGroups.remove(group);
					} else {
						this.addGroup(user.getUserID(), group, con, approvalID, workflow);
					}
				}
				
				if (! addOnly) {
					for (String group : curGroups) {
						this.removeGroup(user.getUserID(), group, con, approvalID, workflow);
					}
				}
				
				
				if (this.createShadowAccount) {
					String password = new BigInteger(130, random).toString(32);
					password = PBKDF2.generateHash(password);
					user.setPassword(password);
					this.setUserPassword(user, request);
				}
				
			}
		} catch (Exception e) {
			throw new ProvisioningException("Could not sync user",e);
		} finally {
			if (con != null) {
				con.getBcm().shutdown();
			}
		} 
		
	}

	private Attribute checkAttribute(User user, User fromIPA, HttpCon con,
			int approvalID, Workflow workflow, String attrName,boolean addOnly)
			throws Exception {
		Attribute attrNew = user.getAttribs().get(attrName);
		if (attrNew != null) {
			Attribute attrOld = fromIPA.getAttribs().get(attrName);
			
			if (attrOld != null) {
				fromIPA.getAttribs().remove(attrName);
				if (attrNew.getValues().size() != attrOld.getValues().size()) {
					//attribute changed, update ipa
					setAttribute(user.getUserID(),attrNew,con,approvalID,workflow);
					
					//determine changes
					
					
					auditAttributeChanges(approvalID, workflow, attrName,
							attrNew, attrOld,addOnly);
					
					
					
					
				} else if (attrOld.getValues().size() == 0 || ! attrOld.getValues().get(0).equals(attrNew.getValues().get(0))) {
					setAttribute(user.getUserID(),attrNew,con,approvalID,workflow);
					this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Replace,  approvalID, workflow, attrName, attrNew.getValues().get(0));
					
				} else {
					HashSet<String> oldVals = new HashSet<String>();
					oldVals.addAll(attrOld.getValues());
					for (String val : attrNew.getValues()) {
						if (! oldVals.contains(val)) {
							setAttribute(user.getUserID(),attrNew,con,approvalID,workflow);
							break;
						} else {
							oldVals.remove(val);
						}
					}
					
					if (oldVals.size() > 0) {
						setAttribute(user.getUserID(),attrNew,con,approvalID,workflow);
					}
					
					//determine changes
					auditAttributeChanges(approvalID, workflow, attrName,
							attrNew, attrOld,addOnly);
				}
			
				
			} else {
				//attribute doesn't exist, update IPA
				setAttribute(user.getUserID(),attrNew,con,approvalID,workflow);
				this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Add,  approvalID, workflow, attrName, attrNew.getValues().get(0));
			}
		}
		return attrNew;
	}

	private void auditAttributeChanges(int approvalID, Workflow workflow,
			String attrName, Attribute attrNew, Attribute attrOld,boolean addOnly)
			throws ProvisioningException {
		HashSet<String> oldVals = new HashSet<String>();
		oldVals.addAll(attrOld.getValues());
		
		for (String val : attrNew.getValues()) {
			if (! oldVals.contains(val)) {
				this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Add,  approvalID, workflow, attrName, val);
				oldVals.remove(val);
			}
		}
		
		if (! addOnly) {
			HashSet<String> newVals = new HashSet<String>();
			newVals.addAll(attrNew.getValues());
			for (String val : attrOld.getValues() ) {
				if (! newVals.contains(val)) {
					this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Delete,  approvalID, workflow, attrName, val);
				}
			}
		}
	}

}
