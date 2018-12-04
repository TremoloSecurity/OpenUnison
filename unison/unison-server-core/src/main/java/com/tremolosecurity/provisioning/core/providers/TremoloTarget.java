/*
Copyright 2015, 2016 Tremolo Security, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/


package com.tremolosecurity.provisioning.core.providers;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.List;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.params.ClientPNames;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.cookie.Cookie;
import org.apache.http.cookie.CookieOrigin;
import org.apache.http.cookie.CookieSpec;
import org.apache.http.cookie.CookieSpecFactory;
import org.apache.http.cookie.MalformedCookieException;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.impl.cookie.BrowserCompatSpec;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.params.HttpParams;
import org.apache.logging.log4j.Logger;

import com.google.gson.Gson;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.ProvisioningParams;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.UserStoreProvider;
import com.tremolosecurity.provisioning.service.util.ProvisioningResult;
import com.tremolosecurity.provisioning.service.util.TremoloUser;
import com.tremolosecurity.provisioning.service.util.WFCall;
import com.tremolosecurity.saml.Attribute;



public class TremoloTarget implements UserStoreProvider {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(TremoloTarget.class.getName());
	
	String createUserWF;
	String setUserPasswordWF;
	String syncUserWF;
	String deleteUserWF;
	
	
	String wfUrlBase;
	String uidAttrName;
	
	ConfigManager cfgMgr;
	int port;

	private String name;
	
	private PoolingHttpClientConnectionManager phcm;
	private CloseableHttpClient httpclient;
	
	
	@Override
	public void createUser(User user, Set<String> attributes,Map<String,Object> request)
			throws ProvisioningException {
		
		this.executeWorkFlow(this.createUserWF, user, attributes,request);

	}

	@Override
	public void setUserPassword(User user,Map<String,Object> request) throws ProvisioningException {
		this.executeWorkFlow(this.setUserPasswordWF, user, new HashSet<String>(),request);

	}

	@Override
	public void syncUser(User user, boolean addOnly, Set<String> attributes,Map<String,Object> request)
			throws ProvisioningException {
		this.executeWorkFlow(this.syncUserWF, user, attributes,request);

	}

	@Override
	public void deleteUser(User user,Map<String,Object> request) throws ProvisioningException {
		this.executeWorkFlow(this.deleteUserWF, user, new HashSet<String>(),request);

	}

	@Override
	public User findUser(String userID, Set<String> attributes,Map<String,Object> request)
			throws ProvisioningException {
		
		
		
		StringBuffer sbUrl = new StringBuffer();
		sbUrl.append(this.wfUrlBase).append("/services/wf/search?uid=").append(userID);
		
		HttpGet httpget = new HttpGet(sbUrl.toString());
		
		try {
			HttpResponse response = httpclient.execute(httpget);
			BufferedReader in = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
			String line = null;
			StringBuffer json = new StringBuffer();
			while ((line = in.readLine()) != null) {
				json.append(line);
			}
			
			Gson gson = new Gson();
			TremoloUser tuser = gson.fromJson(json.toString(), TremoloUser.class);
			
			User toret = new User(tuser.getUid());
			for (Attribute attr : tuser.getAttributes()) {
				if (attributes.contains(attr.getName())) {
					toret.getAttribs().put(attr.getName(), attr);
				}
			}
			
			httpget.abort();
			return toret;
		} catch (Exception e) {
			throw new ProvisioningException("Could not find user",e);
		} finally {
			httpget.releaseConnection();
		}
	}

	@Override
	public void init(Map<String, Attribute> cfg, ConfigManager cfgMgr,String name)
			throws ProvisioningException {
		this.name = name;
		this.cfgMgr = cfgMgr;
		if (cfg.get("createUsersWF") == null) {
			throw new ProvisioningException("Create user workflow not specified");
		}
		
		this.createUserWF = cfg.get("createUsersWF").getValues().get(0);
		
		if (cfg.get("deleteUserWF") == null) {
			throw new ProvisioningException("Delete user workflow not specified");
		}
		this.deleteUserWF = cfg.get("deleteUserWF").getValues().get(0);
		
		if (cfg.get("setUserPasswordWF") == null) {
			throw new ProvisioningException("Set user password workflow not specified");
		}
		this.setUserPasswordWF = cfg.get("setUserPasswordWF").getValues().get(0);
		
		if (cfg.get("syncUserWF") == null) {
			throw new ProvisioningException("Synchronize user workflow not specified");
		}
		this.syncUserWF = cfg.get("syncUserWF").getValues().get(0);
		
		if (cfg.get("uidAttrName") == null) {
			throw new ProvisioningException("User identifier attribute name not found");
		}
		this.uidAttrName = cfg.get("uidAttrName").getValues().get(0);
		
		if (cfg.get("wfUrlBase") == null) {
			throw new ProvisioningException("WorkflowImpl URL base not specified");
		}
		this.wfUrlBase = cfg.get("wfUrlBase").getValues().get(0);
		
		try {
			URL url = new URL(this.wfUrlBase);
			if (url.getPort() > 0) {
				this.port = url.getPort();
			} else {
				this.port = 443;
			}
		} catch (MalformedURLException e) {
			throw new ProvisioningException("Could not configure target",e);
		}
		
		phcm = new PoolingHttpClientConnectionManager(cfgMgr.getHttpClientSocketRegistry());
		httpclient = HttpClients.custom().setConnectionManager(phcm).build();
		
		

	}
	
	

	private void executeWorkFlow(String wfName,User user,Set<String> attributes,Map<String,Object> request) throws ProvisioningException {
		
		
		
		StringBuffer surl = new StringBuffer();
		surl.append(this.wfUrlBase).append("/services/wf/login");
		
		HttpGet get = new HttpGet(surl.toString());
		try {
			try {
				httpclient.execute(get);
			} catch (ClientProtocolException e1) {
				
			} catch (IOException e1) {
				
			}
		} finally {
			get.releaseConnection();
		}
		
		surl.setLength(0);
		surl.append(this.wfUrlBase).append("/services/wf/execute");
		
		HttpPost post = new HttpPost(surl.toString());
		
		try {
		
		TremoloUser tu = new TremoloUser();
		tu.setAttributes(new ArrayList<Attribute>());
		
		tu.setUid(user.getUserID());
		tu.setUserPassword(user.getPassword());
		
		for (String attrName : user.getAttribs().keySet()) {
			Attribute attr = user.getAttribs().get(attrName);
			if (attributes.size() == 0 || attributes.contains(attrName)) {
				tu.getAttributes().add(attr);
			}
		}
		
		WFCall wfcall = new WFCall();
		wfcall.setName(wfName);
		wfcall.setUidAttributeName(this.uidAttrName);
		wfcall.setUser(tu);
		wfcall.setRequestParams(new HashMap<String,Object>());
		wfcall.getRequestParams().put(ProvisioningParams.UNISON_EXEC_TYPE, ProvisioningParams.UNISON_EXEC_SYNC);
		Gson gson = new Gson();
		String jsonOut = gson.toJson(wfcall);
		
		List<NameValuePair> formparams = new ArrayList<NameValuePair>();
		formparams.add(new BasicNameValuePair("wfcall", jsonOut));
		
		UrlEncodedFormEntity entity = new UrlEncodedFormEntity(formparams, "UTF-8");
		
		
		
		post.setEntity(entity);
		
		
		
		HttpResponse response = httpclient.execute(post);
		
		BufferedReader in = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
		String line = null;
		StringBuffer res = new StringBuffer();
		while ((line = in.readLine()) != null) {
			//System.out.println(line);
			res.append(line).append('\n');
		}
		
		ProvisioningResult provRes = gson.fromJson(res.toString(), ProvisioningResult.class);
		
		if (! provRes.isSuccess()) {
			throw new ProvisioningException(provRes.getError().getError());
		}
		
		} catch (Exception e) {
			throw new ProvisioningException("Could not execute workflow",e);
		} finally {
			post.releaseConnection();
		}
		
	}
}
