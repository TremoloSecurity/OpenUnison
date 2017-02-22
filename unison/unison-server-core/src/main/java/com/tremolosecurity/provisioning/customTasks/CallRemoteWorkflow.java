/*******************************************************************************
 * Copyright 2017 Tremolo Security, Inc.
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
package com.tremolosecurity.provisioning.customTasks;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.message.BasicHeader;
import org.apache.logging.log4j.Logger;
import org.joda.time.DateTime;

import com.google.gson.Gson;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.service.util.TremoloUser;
import com.tremolosecurity.provisioning.service.util.WFCall;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;

public class CallRemoteWorkflow implements CustomTask {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(CallRemoteWorkflow.class.getName());
	
	String uidAttributeName;
	String workflowName;
	String lastmileKeyName;
	String url;
	String lastMileUser;
	HashSet<String> fromRequest;
	HashMap<String,String> staticRequest;
	String uri;
	int timeSkew;
	String lastMileUid;
	
	transient WorkflowTask task;
	
	
	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
		this.workflowName = params.get("workflowName").getValues().get(0);
		this.lastmileKeyName = params.get("lastMileKeyName").getValues().get(0);
		this.url = params.get("url").getValues().get(0);
		this.fromRequest = new HashSet<String>();
		this.staticRequest = new HashMap<String,String>();
		this.lastMileUid = params.get("lastMileUid").getValues().get(0);
		this.uidAttributeName = params.get("uidAttributeName").getValues().get(0);
		Attribute attr = params.get("attributeFromRequest");
		if (attr != null) {
			this.fromRequest.addAll(attr.getValues());
		}
		
		attr = params.get("staticRequestValues");
		if (attr != null) {
			for (String p : attr.getValues()) {
				String name = p.substring(0,p.indexOf('='));
				String val = p.substring(p.indexOf('=') + 1);
				this.staticRequest.put(name, val);
			}
		}
		
		this.lastMileUser = params.get("lastMileUser").getValues().get(0);
		this.timeSkew = Integer.parseInt(params.get("timeSkew").getValues().get(0));
		
		this.task = task;
		
		try {
			URL uurl = new URL(this.url);
			this.uri = uurl.getPath();
		} catch (MalformedURLException e) {
			throw new ProvisioningException("Could not initialize",e);
		}

	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
		this.task = task;

	}

	@Override
	public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {
		
		HashMap<String,Object> newRequest = new HashMap<String,Object>();
		for (String name : this.fromRequest) {
			newRequest.put(name, request.get(name));
		}
		
		for (String key : this.staticRequest.keySet()) {
			newRequest.put(key, this.staticRequest.get(key));
		}
		
		WFCall wfCall = new WFCall();
		wfCall.setName(this.workflowName);
		wfCall.setRequestParams(newRequest);
		wfCall.setUser(new TremoloUser());
		wfCall.getUser().setUid(user.getUserID());
		wfCall.getUser().setUserPassword(user.getPassword());
		wfCall.getUser().setGroups(user.getGroups());
		wfCall.getUser().setAttributes(new ArrayList<Attribute>());
		wfCall.getUser().getAttributes().addAll(user.getAttribs().values());
		wfCall.setUidAttributeName(uidAttributeName);
		wfCall.setReason(task.getWorkflow().getUser().getRequestReason());
		if (task.getWorkflow().getRequester() != null) {
			wfCall.setRequestor(task.getWorkflow().getRequester().getUserID());
		} else {
			wfCall.setRequestor(this.lastMileUser);
		}
		
		DateTime notBefore = new DateTime();
		notBefore = notBefore.minusSeconds(timeSkew);
		DateTime notAfter = new DateTime();
		notAfter = notAfter.plusSeconds(timeSkew);
		
		com.tremolosecurity.lastmile.LastMile lastmile = null;
		
		try {
			lastmile = new com.tremolosecurity.lastmile.LastMile(this.uri,notBefore,notAfter,0,"oauth2");
			
		} catch (URISyntaxException e) {
			throw new ProvisioningException("Could not generate lastmile",e);
		}
		
		Attribute attrib = new Attribute(this.lastMileUid,this.lastMileUser);
		lastmile.getAttributes().add(attrib);
		String encryptedXML = null;
		
		try {
			encryptedXML = lastmile.generateLastMileToken(this.task.getConfigManager().getSecretKey(this.lastmileKeyName));
		} catch (Exception e) {
			throw new ProvisioningException("Could not generate lastmile",e);
		}
		
		StringBuffer header = new StringBuffer();
		header.append("Bearer " ).append(encryptedXML);
		
		BasicHttpClientConnectionManager bhcm = null;
		CloseableHttpClient http = null;
		
		try {
			bhcm = new BasicHttpClientConnectionManager(
					this.task.getConfigManager().getHttpClientSocketRegistry());
	
			RequestConfig rc = RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD).setRedirectsEnabled(false)
					.build();
	
			http = HttpClients.custom()
					                  .setConnectionManager(bhcm)
					                  .setDefaultRequestConfig(rc)
					                  .build();
			
			HttpPost post = new HttpPost(this.url);
			post.addHeader(new BasicHeader("Authorization",header.toString()));
			
			Gson gson = new Gson();
			StringEntity str = new StringEntity(gson.toJson(wfCall),ContentType.APPLICATION_JSON);
			post.setEntity(str);
			
			
			HttpResponse resp = http.execute(post);
			if (resp.getStatusLine().getStatusCode() != 200) {
				throw new ProvisioningException("Call failed");
			}
			
		} catch (IOException e) {
			throw new ProvisioningException("Could not make call",e);
		} finally {
			if (http != null) {
				try {
					http.close();
				} catch (IOException e) {
					logger.warn(e);
				}
			}
			
			if (bhcm != null) {
				bhcm.close();
			}
			
		}
		
		
		return true;
	}

}
