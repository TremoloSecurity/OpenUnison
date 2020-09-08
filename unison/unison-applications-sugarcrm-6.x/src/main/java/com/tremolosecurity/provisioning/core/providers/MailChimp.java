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
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.http.Header;
import org.apache.http.ParseException;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
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
import org.apache.http.util.EntityUtils;
import org.apache.logging.log4j.Logger;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.UserStoreProvider;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;


public class MailChimp implements UserStoreProvider {
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(MailChimp.class.getName());
	
	String apiKey;
	String host;
	Set<String> mergeAttributes;
	
	transient ConfigManager cfgMgr;

	private Map<String,Long> getTags(String listID) throws Exception {
		HashMap<String,Long> tags = new HashMap<String,Long>();
		
		StringBuffer sb = new StringBuffer();
		HttpCon con = null;
		try {
			con = this.createClient();
			sb.append("https://").append(this.host).append("/3.0/lists/").append(URLEncoder.encode(listID, "UTF-8")).append("/segments");
			
			HttpGet get = new HttpGet(sb.toString());
			
			get.addHeader("Authorization","Basic " + new String(java.util.Base64.getEncoder().encode(("x:" + apiKey).getBytes("UTF-8"))));
			CloseableHttpResponse resp = con.getHttp().execute(get);
			
			JSONArray segments = (JSONArray) ((JSONObject)new JSONParser().parse(EntityUtils.toString(resp.getEntity()))).get("segments");
			
			for (Object o : segments) {
				JSONObject tag = (JSONObject) o;
				tags.put((String) tag.get("name"), (Long) tag.get("id"));
				
			}
			
			return tags;
		} finally {
			if (con != null) {
				try {
					con.getHttp().close();
				} catch (IOException e) {
					
				}
				con.getBcm().close();
			}
		}
		
	}
	
	@Override
	public void createUser(User user, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		String listID = (String) request.get("listID");
		
		JSONObject member = new JSONObject();
		member.put("email_address", user.getUserID());
		JSONObject merge = new JSONObject();
		member.put("merge_fields", merge);
		for (Attribute attr : user.getAttribs().values()) {
			if (attributes.contains(attr.getName())) {
				if (attr.getName().equals("tags")) {
					
					JSONArray tagList = new JSONArray();
					for (String tagName : attr.getValues()) {
						tagList.add(tagName);
					}
					
					member.put("tags", tagList);
					
				} else if (this.mergeAttributes.contains(attr.getName())) {
					merge.put(attr.getName(), attr.getValues().get(0));
				} else {
					member.put(attr.getName(), attr.getValues().get(0));
				}
			}
		}
		
		String json = member.toJSONString();
		
		
		
		
		StringBuffer sb = new StringBuffer();
		try {
			sb.append("https://").append(this.host).append("/3.0/lists/").append(URLEncoder.encode(listID, "UTF-8")).append("/members");
		} catch (UnsupportedEncodingException e1) {
			
		}
		String url = sb.toString();
		
		HttpCon con = null;
		try {
			con = this.createClient();
			HttpPost post = new HttpPost(sb.toString());
			
			post.addHeader("Authorization","Basic " + new String(java.util.Base64.getEncoder().encode(("x:" + apiKey).getBytes("UTF-8"))));
			StringEntity str = new StringEntity(json,ContentType.APPLICATION_JSON);
			post.setEntity(str);
			CloseableHttpResponse resp = con.getHttp().execute(post);
			
			if (resp.getStatusLine().getStatusCode() != 200) {
				logger.error("Could not create '" + user.getUserID() + "' - " + resp.getStatusLine().getStatusCode() + " - " + EntityUtils.toString(resp.getEntity()));
				
			} 
			
			String jsonResp = EntityUtils.toString(resp.getEntity());
			
		} catch (Exception e) {
			logger.warn("Could not get connection",e);
			
		} finally {
			if (con != null) {
				try {
					con.getHttp().close();
				} catch (IOException e) {
					
				}
				con.getBcm().close();
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
		
		CloseableHttpResponse resp = null;
		String respJson = getUserJSON(user.getUserID(), request, resp);
		
		if (respJson != null) {
			String listID = (String) request.get("listID");
			
			JSONObject root;
			try {
				root = (JSONObject) new JSONParser().parse(respJson);
			} catch (ParseException | org.json.simple.parser.ParseException  e) {
				logger.warn("Could not parse json",e);
				return ;
			}
			JSONObject exactMatches = (JSONObject) root.get("exact_matches");
			JSONArray members = (JSONArray) exactMatches.get("members");
			
			if (members.size() == 0) {
				//logger.error("Could not find '" + user.getUserID() + "'");
				this.createUser(user, attributes, request);
				return ;
			}
			
			JSONObject member = (JSONObject) members.get(0);
			
			String id = (String) member.get("id");
			
			
			member = new JSONObject();
			member.put("email_address", user.getUserID());
			JSONObject merge = new JSONObject();
			member.put("merge_fields", merge);
			for (Attribute attr : user.getAttribs().values()) {
				if (attributes.contains(attr.getName())) {
					if (attr.getName().equals("tags")) {
						
						JSONArray tagList = new JSONArray();
						for (String tagName : attr.getValues()) {
							tagList.add(tagName);
						}
						
						member.put("tags", tagList);
						
					} else if (this.mergeAttributes.contains(attr.getName())) {
						merge.put(attr.getName(), attr.getValues().get(0));
					} else {
						member.put(attr.getName(), attr.getValues().get(0));
					}
				}
			}
			
			String json = member.toJSONString();
			
			
			
			StringBuffer sb = new StringBuffer();
			try {
				sb.append("https://").append(this.host).append("/3.0/lists/").append(URLEncoder.encode(listID, "UTF-8")).append("/members/").append(URLEncoder.encode(id,"UTF-8"));
			} catch (UnsupportedEncodingException e1) {
				
			}
			String url = sb.toString();
			
			HttpCon con = null;
			try {
				con = this.createClient();
				HttpPatch post = new HttpPatch(sb.toString());
				
				post.addHeader("Authorization","Basic " + new String(java.util.Base64.getEncoder().encode(("x:" + apiKey).getBytes("UTF-8"))));
				StringEntity str = new StringEntity(json,ContentType.APPLICATION_JSON);
				post.setEntity(str);
				resp = con.getHttp().execute(post);
				
				if (resp.getStatusLine().getStatusCode() != 200) {
					logger.error("Could not create '" + user.getUserID() + "' - " + resp.getStatusLine().getStatusCode() + " - " + EntityUtils.toString(resp.getEntity()));
					
				} 
				
				String jsonResp = EntityUtils.toString(resp.getEntity());
				
			} catch (Exception e) {
				logger.warn("Could not get connection",e);
				
			} finally {
				if (con != null) {
					try {
						con.getHttp().close();
					} catch (IOException e) {
						
					}
					con.getBcm().close();
				}
			}
		} else {
			this.createUser(user, attributes, request);
		}
		
	}

	@Override
	public void deleteUser(User user, Map<String, Object> request) throws ProvisioningException {
		
		CloseableHttpResponse resp = null;
		
		String respJson = getUserJSON(user.getUserID(), request, resp);
		
		if (respJson == null) {
			return ;
		}
		
		JSONObject root;
		try {
			root = (JSONObject) new JSONParser().parse(respJson);
		} catch (ParseException | org.json.simple.parser.ParseException  e) {
			logger.warn("Could not parse json",e);
			return ;
		}
		JSONObject exactMatches = (JSONObject) root.get("exact_matches");
		JSONArray members = (JSONArray) exactMatches.get("members");
		
		if (members.size() == 0) {
			logger.error("Could not find '" + user.getUserID() + "'");
			return ;
		}
		
		JSONObject member = (JSONObject) members.get(0);
		
		String id = (String) member.get("id");
		
		String listID = (String) request.get("listID");
		StringBuffer sb = new StringBuffer();
		try {
			sb.append("https://").append(this.host).append("/3.0/lists/").append(URLEncoder.encode(listID, "UTF-8")).append("/members/").append(URLEncoder.encode(id,"UTF-8"));
		} catch (UnsupportedEncodingException e1) {
			
		}
		String url = sb.toString();
		
		
		HttpCon con = null;
		try {
			con = this.createClient();
			HttpDelete post = new HttpDelete(sb.toString());
			
			post.addHeader("Authorization","Basic " + new String(java.util.Base64.getEncoder().encode(("x:" + apiKey).getBytes("UTF-8"))));
			
			resp = con.getHttp().execute(post);
			
			if (resp.getStatusLine().getStatusCode() != 204) {
				logger.error("Could not create '" + user.getUserID() + "' - " + resp.getStatusLine().getStatusCode() );
				
			} 
		} catch (Exception e) {
			logger.warn("Could not get connection",e);
			
		} finally {
			if (con != null) {
				try {
					con.getHttp().close();
				} catch (IOException e) {
					
				}
				con.getBcm().close();
			}
		}
		
	}

	@Override
	public User findUser(String userID, Set<String> attributes, Map<String, Object> request) {
		CloseableHttpResponse resp = null;
		
		String respJson = getUserJSON(userID, request, resp);
		
		if (respJson == null) {
			return null;
		}
		
		User user = new User(userID);
		
		JSONObject root;
		try {
			root = (JSONObject) new JSONParser().parse(respJson);
		} catch (ParseException | org.json.simple.parser.ParseException  e) {
			logger.warn("Could not parse json",e);
			return null;
		}
		JSONObject exactMatches = (JSONObject) root.get("exact_matches");
		JSONArray members = (JSONArray) exactMatches.get("members");
		
		if (members.size() == 0) {
			logger.error("Could not find '" + userID + "'");
			return null;
		}
		
		JSONObject member = (JSONObject) members.get(0);
		JSONObject merge = (JSONObject) member.get("merge_fields");
		for (String attribute : attributes) {
			if (attribute.equalsIgnoreCase("tags")) {
				JSONArray tags = (JSONArray) member.get("tags");
				Attribute tagsAttr = new Attribute("tags");
				user.getAttribs().put("tags", tagsAttr);
				for (Object o : tags) {
					JSONObject tag = (JSONObject)o;
					tagsAttr.getValues().add((String)tag.get("name")); 
				}
				
			} else {
				Object o = member.get(attribute);
				if (o != null && o instanceof String) {
					user.getAttribs().put(attribute, new Attribute(attribute,(String)o));
				} else {
					o = merge.get(attribute);
					if (o != null && o instanceof String) {
						user.getAttribs().put(attribute, new Attribute(attribute,(String)o));
					}
					
				}
			}
			
			
		}
		
		return user;
			
	}

	private String getUserJSON(String userID, Map<String, Object> request, CloseableHttpResponse resp) {
		String listID = (String) request.get("listID");
		StringBuffer sb = new StringBuffer();
		try {
			sb.append("https://").append(this.host).append("/3.0/search-members?query=").append(URLEncoder.encode(userID, "UTF-8")).append("&list_id=").append(URLEncoder.encode(listID,"UTF-8"));
		} catch (UnsupportedEncodingException e1) {
			
		}
		String url = sb.toString();
		
		HttpCon con = null;
		String json = null;
		try {
			con = this.createClient();
			HttpGet get = new HttpGet(sb.toString());
			
			get.addHeader("Authorization","Basic " + new String(java.util.Base64.getEncoder().encode(("x:" + apiKey).getBytes("UTF-8"))));
			resp = con.getHttp().execute(get);
			
			if (resp.getStatusLine().getStatusCode() == 200) {
				
			} else if (resp.getStatusLine().getStatusCode() == 404) {
				logger.error("Could not find '" + userID + "' - " + resp.getStatusLine().getStatusCode() + " - " + EntityUtils.toString(resp.getEntity()));
				return null;
			} else {
				logger.error("Could not find '" + userID + "' - " + resp.getStatusLine().getStatusCode() + " - " + EntityUtils.toString(resp.getEntity()));
				return null;
			}
			
			json = EntityUtils.toString(resp.getEntity());
			
		} catch (Exception e) {
			logger.warn("Could not get connection",e);
			return null;
		} finally {
			if (con != null) {
				try {
					con.getHttp().close();
				} catch (IOException e) {
					
				}
				con.getBcm().close();
			}
		}
		return json;
	}

	@Override
	public void init(Map<String, Attribute> cfg, ConfigManager cfgMgr, String name) throws ProvisioningException {
		this.apiKey = cfg.get("apiKey").getValues().get(0);
		this.host = cfg.get("host").getValues().get(0);
		
		this.mergeAttributes = new HashSet<String>();
		this.mergeAttributes.addAll(cfg.get("mergeAttributes").getValues());
		this.cfgMgr = cfgMgr;
		
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

	@Override
	public void shutdown() throws ProvisioningException {
		// TODO Auto-generated method stub
		
	}

}
