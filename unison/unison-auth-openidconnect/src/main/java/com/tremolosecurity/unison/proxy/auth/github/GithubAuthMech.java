/*******************************************************************************
 * Copyright 2015, 2017, 2019 Tremolo Security, Inc.
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
package com.tremolosecurity.unison.proxy.auth.github;

import static org.apache.directory.ldap.client.api.search.FilterBuilder.equal;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.tremolosecurity.proxy.TremoloHttpSession;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.NameValuePair;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.message.BasicHeader;
import org.apache.log4j.Logger;
import org.jose4j.json.internal.json_simple.JSONArray;
import org.jose4j.json.internal.json_simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.google.gson.Gson;
import com.google.gson.stream.JsonReader;
import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.AuthMechType;

import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.auth.AuthMechanism;
import com.tremolosecurity.proxy.auth.RequestHolder;
import com.tremolosecurity.proxy.auth.util.AuthStep;

import com.tremolosecurity.proxy.myvd.MyVDConnection;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.proxy.auth.openidconnect.sdk.LoadUserData;
import com.tremolosecurity.util.JsonTools;



public class GithubAuthMech implements AuthMechanism {

	static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(GithubAuthMech.class.getName());
	
	
	
	public void init(ServletContext ctx, HashMap<String, Attribute> init) {
		// TODO Auto-generated method stub

	}

	public String getFinalURL(HttpServletRequest request, HttpServletResponse response) {
		
		return null;
	}

	public void doGet(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		
		HttpSession session = ((HttpServletRequest) request).getSession();
		HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
		ConfigManager cfg = (ConfigManager) request.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);
		
		MyVDConnection myvd = cfg.getMyVD();
		
		String bearerTokenName = authParams.get("bearerTokenName").getValues().get(0);
		String clientid = authParams.get("clientid").getValues().get(0);
		String secret = authParams.get("secretid").getValues().get(0);
		String idpURL = authParams.get("idpURL") != null ? authParams.get("idpURL").getValues().get(0) : "https://github.com/login/oauth/authorize";
		
		String scope = authParams.get("scope").getValues().get(0);
		boolean linkToDirectory = Boolean.parseBoolean(authParams.get("linkToDirectory").getValues().get(0));
		String noMatchOU = authParams.get("noMatchOU").getValues().get(0);
		String uidAttr = authParams.get("uidAttr").getValues().get(0);
		String lookupFilter = authParams.get("lookupFilter").getValues().get(0);
		
		String githubApiUrl = "https://api.github.com";
		if (authParams.get("apiUrl") != null) {
			githubApiUrl = authParams.get("apiUrl").getValues().get(0);
		}
		
		
		String defaultObjectClass = authParams.get("defaultObjectClass").getValues().get(0);
		
		boolean forceAuth = true;//authParams.get("forceAuthentication") != null ? authParams.get("forceAuthentication").getValues().get(0).equalsIgnoreCase("true") : false;
		
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		RequestHolder reqHolder = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
		
		
		
		
		StringBuffer b = new StringBuffer();
		
		URL reqURL = new URL(request.getRequestURL().toString());

		b.append(reqURL.getProtocol()).append("://").append(reqURL.getHost());


		if (reqURL.getPort() != -1) {
			b.append(":").append(reqURL.getPort());
		}
		
		String urlChain = holder.getUrl().getAuthChain();
		AuthChainType act = holder.getConfig().getAuthChains().get(reqHolder.getAuthChainName());
		
		
		
		
		AuthMechType amt = act.getAuthMech().get(as.getId());
		
		String authMechName = amt.getName();


		b.append(holder.getConfig().getContextPath()).append(cfg.getAuthMechs().get(authMechName).getUri());
		
		
		
		String loadTokenURL = authParams.get("loadTokenURL") != null ? authParams.get("loadTokenURL").getValues().get(0) : "https://github.com/login/oauth/access_token";
		
		
		if (request.getParameter("state") == null) {
			//initialize openidconnect
			
			String state = new BigInteger(130, new SecureRandom()).toString(32);
			request.getSession().setAttribute("UNISON_OPENIDCONNECT_STATE", state);
			
			StringBuffer redirToSend = new StringBuffer();
			redirToSend.append(idpURL)
						.append("?client_id=").append(URLEncoder.encode(clientid,"UTF-8"))
						.append("&scope=").append(URLEncoder.encode(scope,"UTF-8"))
						.append("&state=").append(URLEncoder.encode("security_token=","UTF-8")).append(URLEncoder.encode(state, "UTF-8"));
			
			response.sendRedirect(redirToSend.toString());
						
		} else {
			String stateFromURL = request.getParameter("state");
			stateFromURL = URLDecoder.decode(stateFromURL,"UTF-8");
			stateFromURL = stateFromURL.substring(stateFromURL.indexOf('=') + 1);
			
			String stateFromSession = (String) request.getSession().getAttribute("UNISON_OPENIDCONNECT_STATE");
			
			if (! stateFromSession.equalsIgnoreCase(stateFromURL)) {
				throw new ServletException("Invalid State");
			}
		
			HttpUriRequest post = null;
			
			try {
				post = RequestBuilder.post()
				        .setUri(new java.net.URI(loadTokenURL))
				        .addParameter("code", request.getParameter("code"))
				        .addParameter("client_id", clientid)
				        .addParameter("client_secret", secret)
				        .build();
			} catch (URISyntaxException e) {
				throw new ServletException("Could not create post request");
			}
			
			BasicHttpClientConnectionManager bhcm = new BasicHttpClientConnectionManager(GlobalEntries.getGlobalEntries().getConfigManager().getHttpClientSocketRegistry());
			RequestConfig rc = RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD).build();
			CloseableHttpClient http = HttpClients.custom().setConnectionManager(bhcm).setDefaultRequestConfig(rc).build();
			  
			try {
				CloseableHttpResponse httpResp = http.execute(post);
				
				BufferedReader in = new BufferedReader(new InputStreamReader(httpResp.getEntity().getContent()));
				
				StringBuffer token = new StringBuffer();
				
				
				String line = null;
				while ((line = in.readLine()) != null) {
					token.append(line);
				}
				
				
				
				List<NameValuePair> params = URLEncodedUtils.parse(token.toString(), Charset.defaultCharset());
				
				String accessToken = null;
				
				for (NameValuePair nvp : params) {
					if (nvp.getName().equals("access_token")) {
						accessToken = nvp.getValue();
					}
				}
				
				if (accessToken == null) {
					throw new ServletException("Could not get authorization toekn : " + token);
				}
				
				
				
				httpResp.close();
				
				
				Gson gson = new Gson();
				
				
				HttpGet get = new HttpGet(String.format("%s/user",githubApiUrl));
				
				get.addHeader("Authorization",new StringBuilder().append("Bearer ").append(accessToken).toString());
				
				
				//Store the bearer token for use by Unison
				request.getSession().setAttribute(bearerTokenName, accessToken);
				
				
				httpResp = http.execute(get);
				
				in = new BufferedReader(new InputStreamReader(httpResp.getEntity().getContent()));
				
				token.setLength(0);
				
				
				line = null;
				while ((line = in.readLine()) != null) {
					token.append(line);
				}
				
				
				httpResp.close();
				
				
				
				
				Map jwtNVP =  JsonTools.jsonToMap(token.toString());
				
				
				
				
				if (jwtNVP == null) {
					as.setSuccess(false);
				} else {
					
					get = new HttpGet(String.format("%s/user/emails",githubApiUrl));
					get.addHeader("Authorization",new StringBuilder().append("Bearer ").append(accessToken).toString());
					httpResp = http.execute(get);
					in = new BufferedReader(new InputStreamReader(httpResp.getEntity().getContent()));
					token.setLength(0);
					line = null;
					while ((line = in.readLine()) != null) {
						token.append(line);
					}
					
					
					
					httpResp.close();
					
					
					JSONParser parser = new JSONParser();
					org.json.simple.JSONArray emails = (org.json.simple.JSONArray) parser.parse(token.toString());
					
					
					
					for (Object o : emails) {
						org.json.simple.JSONObject emailObj = (org.json.simple.JSONObject) o;
						boolean isPrimary = (Boolean) emailObj.get("primary");
						if (isPrimary) {
							jwtNVP.put("mail", emailObj.get("email"));
						}
						
					}
					
					
					if (! linkToDirectory) {
						loadUnlinkedUser(session, noMatchOU, uidAttr, act, jwtNVP,defaultObjectClass);
						
						as.setSuccess(true);
	
						
					} else {
						lookupUser(as, session, myvd, noMatchOU, uidAttr, lookupFilter, act, jwtNVP,defaultObjectClass);
					}
					
					get = new HttpGet(String.format("%s/user/orgs",githubApiUrl));
					get.addHeader("Authorization", new StringBuilder().append("Bearer ").append(accessToken).toString());
					httpResp = http.execute(get);
					in = new BufferedReader(new InputStreamReader(httpResp.getEntity().getContent()));
					token.setLength(0);
					line = null;
					while ((line = in.readLine()) != null) {
						token.append(line);
					}
					httpResp.close();
					
					parser = new JSONParser();
					org.json.simple.JSONArray orgs = (org.json.simple.JSONArray) parser.parse(token.toString());
					
					Attribute userOrgs = new Attribute("githubOrgs");
					Attribute userTeams = new Attribute("githubTeams");
					
					for (Object o : orgs) {
						org.json.simple.JSONObject org = (org.json.simple.JSONObject) o;
						String orgName = (String) org.get("login");
						userOrgs.getValues().add(orgName);
						
						
						HttpUriRequest graphql = RequestBuilder.post()
								.addHeader(new BasicHeader("Authorization","Bearer " + accessToken))
								.setUri(String.format("%s/graphql",githubApiUrl))
								.setEntity(new StringEntity("{\"query\":\"{organization(login: \\\"" + orgName + "\\\") { teams(first: 100, userLogins: [\\\"" + jwtNVP.get("login") + "\\\"]) { totalCount edges {node {name description}}}}}\"}")).build();
			
						
						httpResp = http.execute(graphql);
						in = new BufferedReader(new InputStreamReader(httpResp.getEntity().getContent()));
						token.setLength(0);
						line = null;
						while ((line = in.readLine()) != null) {
							token.append(line);
						}
						
						
						
						httpResp.close();
						
						org.json.simple.JSONObject root = (org.json.simple.JSONObject) parser.parse(token.toString());
						org.json.simple.JSONObject data = (org.json.simple.JSONObject) root.get("data");
						org.json.simple.JSONObject organization = (org.json.simple.JSONObject) data.get("organization");
						org.json.simple.JSONObject teams = (org.json.simple.JSONObject) organization.get("teams");
						org.json.simple.JSONArray edges = (org.json.simple.JSONArray) teams.get("edges"); 
						
						for (Object oi : edges) {
							org.json.simple.JSONObject edge = (org.json.simple.JSONObject) oi;
							org.json.simple.JSONObject node = (org.json.simple.JSONObject) edge.get("node");
							userTeams.getValues().add(orgName + "/" + node.get("name"));
						}
						
						
					}
					
					
										
							
							
							
							
							
					
					
					
					((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo().getAttribs().put("githubOrgs", userOrgs);
					((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo().getAttribs().put("githubTeams", userTeams);
					
					String redirectToURL = request.getParameter("target");
					if (redirectToURL != null && ! redirectToURL.isEmpty()) {
						reqHolder.setURL(redirectToURL);
					}
				}
				
				
				
				
				
				
				
				holder.getConfig().getAuthManager().nextAuth(request, response,session,false);
			
			} catch (ParseException e) {
				throw new ServletException("Could not parse orgs",e);
			} finally {
				if (bhcm != null) {
					bhcm.close();
				}
				
				if (http != null) {
					http.close();
				}
			}
			
			
		}
		
		

	}

	public static void lookupUser(AuthStep as, HttpSession session, MyVDConnection myvd, String noMatchOU, String uidAttr,
			String lookupFilter, AuthChainType act, Map jwtNVP,String defaultObjectClass) {
		boolean uidIsFilter = ! lookupFilter.isEmpty();
		
		
		String filter = "";
		if (uidIsFilter) {
			StringBuffer b = new StringBuffer();
			int lastIndex = 0;
			int index = lookupFilter.indexOf('$');
			while (index >= 0) {
				b.append(lookupFilter.substring(lastIndex,index));
				lastIndex = lookupFilter.indexOf('}',index) + 1;
				String reqName = lookupFilter.substring(index + 2,lastIndex - 1);
				b.append(jwtNVP.get(reqName).toString());
				index = lookupFilter.indexOf('$',index+1);
			}
			b.append(lookupFilter.substring(lastIndex));
			filter = b.toString();
			if (logger.isDebugEnabled()) {
				logger.debug("Filter : '" + filter + "'");
			}
		} else {
			StringBuffer b = new StringBuffer();
			String userParam = (String) jwtNVP.get(uidAttr);
			b.append('(').append(uidAttr).append('=').append(userParam).append(')');
			if (userParam == null) {
				filter = "(!(objectClass=*))";
			} else {
				filter = equal(uidAttr,userParam).toString();
			}
		}
		
		try {
			
			String root = act.getRoot();
			if (root == null || root.trim().isEmpty()) {
				root = GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getLdapRoot();
			}
			
			LDAPSearchResults res = myvd.search(root, 2, filter, new ArrayList<String>());
			
			if (res.hasMore()) {
				LDAPEntry entry = res.next();
				while (res.hasMore()) res.next();
				
				Iterator<LDAPAttribute> it = entry.getAttributeSet().iterator();
				AuthInfo authInfo = new AuthInfo(entry.getDN(),(String) session.getAttribute(ProxyConstants.AUTH_MECH_NAME),act.getName(),act.getLevel(),(TremoloHttpSession) session);
				((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).setAuthInfo(authInfo);
				
				while (it.hasNext()) {
					LDAPAttribute attrib = it.next();
					Attribute attr = new Attribute(attrib.getName());
					String[] vals = attrib.getStringValueArray();
					for (int i=0;i<vals.length;i++) {
						attr.getValues().add(vals[i]);
					}
					authInfo.getAttribs().put(attr.getName(), attr);
				}
				
				for (Object o : jwtNVP.keySet()) {
					String s = (String) o;
					
					
					
					Object v = jwtNVP.get(s);
					
					Attribute attr = authInfo.getAttribs().get(s);
					if (attr == null) {
						attr = new Attribute(s);
						authInfo.getAttribs().put(attr.getName(), attr);
					}
					
					
					if (v instanceof String) {
						String val = (String) v;
						if (! attr.getValues().contains(val)) {
							attr.getValues().add(val);
						}
					} else if (v instanceof Object[]) {
						for (Object vo : ((Object[])v)) {
							String vv = (String) vo;
							if (vv != null && ! attr.getValues().contains(vv)) {
								attr.getValues().add(vv);
							}
						}
					}
					
					
					
					
					
							
					
					
					
				}
				
				as.setSuccess(true);
				
				
				
			} else {
				
				loadUnlinkedUser(session, noMatchOU, uidAttr, act, jwtNVP,defaultObjectClass);
				
				as.setSuccess(true);
			}
			
		} catch (LDAPException e) {
			if (e.getResultCode() != LDAPException.INVALID_CREDENTIALS) {
				logger.error("Could not authenticate user",e);
			} 
			
			
			as.setSuccess(false);
		}
	}

	public static void loadUnlinkedUser(HttpSession session, String noMatchOU, String uidAttr, AuthChainType act,
			Map jwtNVP,String defaultObjectClass) {
		String uid = (String) jwtNVP.get(uidAttr);
		StringBuffer dn = new StringBuffer();
		dn.append(uidAttr).append('=').append(uid).append(",ou=").append(noMatchOU).append(",").append(GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getLdapRoot());
		
		AuthInfo authInfo = new AuthInfo(dn.toString(),(String) session.getAttribute(ProxyConstants.AUTH_MECH_NAME),act.getName(),act.getLevel(),(TremoloHttpSession) session);
		((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).setAuthInfo(authInfo);
		
		for (Object o : jwtNVP.keySet()) {
			String s = (String) o;
			
			Attribute attr;
			
			Object oAttr = jwtNVP.get(s);
			
			if (oAttr != null) {
				if (logger.isDebugEnabled()) {
					logger.debug(s + " type - '" + oAttr.getClass().getName() + "'");
				}
				
				if (oAttr.getClass().isArray()) {
					attr = new Attribute(s);
					Object[] objArray = (Object[]) oAttr;
					for (Object v : objArray) {
						attr.getValues().add(v.toString());
					}
				} else {
					attr = new Attribute(s,oAttr.toString());
				}
				
				 
				authInfo.getAttribs().put(attr.getName(), attr);
			}
		}
		
		authInfo.getAttribs().put("objectClass", new Attribute("objectClass",defaultObjectClass));
	}

	public void doPost(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);

	}

	public void doPut(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);

	}

	public void doHead(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);

	}

	public void doOptions(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);

	}

	public void doDelete(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);

	}

}
