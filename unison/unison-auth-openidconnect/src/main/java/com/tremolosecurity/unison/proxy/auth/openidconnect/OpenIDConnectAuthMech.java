/*******************************************************************************
 * Copyright 2015, 2016 Tremolo Security, Inc.
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
package com.tremolosecurity.unison.proxy.auth.openidconnect;

import static org.apache.directory.ldap.client.api.search.FilterBuilder.equal;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.UUID;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.httpclient.URI;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.log4j.Logger;


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



public class OpenIDConnectAuthMech implements AuthMechanism {

	static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(OpenIDConnectAuthMech.class.getName());
	
	
	
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
		String idpURL = authParams.get("idpURL").getValues().get(0);
		String responseType = authParams.get("responseType").getValues().get(0);
		String scope = authParams.get("scope").getValues().get(0);
		boolean linkToDirectory = Boolean.parseBoolean(authParams.get("linkToDirectory").getValues().get(0));
		String noMatchOU = authParams.get("noMatchOU").getValues().get(0);
		String uidAttr = authParams.get("uidAttr").getValues().get(0);
		String lookupFilter = authParams.get("lookupFilter").getValues().get(0);
		String userLookupClassName = authParams.get("userLookupClassName").getValues().get(0);
		
		String defaultObjectClass = authParams.get("defaultObjectClass").getValues().get(0);
		
		boolean forceAuth = true;//authParams.get("forceAuthentication") != null ? authParams.get("forceAuthentication").getValues().get(0).equalsIgnoreCase("true") : false;
		
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		RequestHolder reqHolder = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
		
		
		
		
		
		
		URL reqURL = new URL(request.getRequestURL().toString());
		String redirectURL = reqURL.getProtocol() + "://" + reqURL.getHost();
		if (reqURL.getPort() != -1) {
			redirectURL += ":" + reqURL.getPort();
		}
		
		String urlChain = holder.getUrl().getAuthChain();
		AuthChainType act = holder.getConfig().getAuthChains().get(reqHolder.getAuthChainName());
		
		
		
		
		AuthMechType amt = act.getAuthMech().get(as.getId());
		
		String authMechName = amt.getName();
		redirectURL += cfg.getAuthMechs().get(authMechName).getUri();
		
		
		String hd = authParams.get("hd").getValues().get(0);
		String loadTokenURL = authParams.get("loadTokenURL").getValues().get(0);
		
		
		if (request.getParameter("state") == null) {
			//initialize openidconnect
			
			String state = new BigInteger(130, new SecureRandom()).toString(32);
			request.getSession().setAttribute("UNISON_OPENIDCONNECT_STATE", state);
			
			StringBuffer redirToSend = new StringBuffer();
			redirToSend.append(idpURL)
						.append("?client_id=").append(URLEncoder.encode(clientid,"UTF-8"))
						.append("&response_type=").append(URLEncoder.encode(responseType, "UTF-8"))
						.append("&scope=").append(URLEncoder.encode(scope,"UTF-8"))
						.append("&redirect_uri=").append(URLEncoder.encode(redirectURL,"UTF-8"))
						.append("&state=").append(URLEncoder.encode("security_token=","UTF-8")).append(URLEncoder.encode(state, "UTF-8"));
			
			if (forceAuth) {
				redirToSend.append("&max_age=0");
			}
			
			if (! hd.isEmpty()) {
				redirToSend.append("&hd=").append(hd);
			}
			
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
				        .addParameter("redirect_uri", redirectURL)
				        .addParameter("grant_type", "authorization_code")
				        .build();
			} catch (URISyntaxException e) {
				throw new ServletException("Could not create post request");
			}
			
			BasicHttpClientConnectionManager bhcm = new BasicHttpClientConnectionManager(GlobalEntries.getGlobalEntries().getConfigManager().getHttpClientSocketRegistry());
			RequestConfig rc = RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD).build();
			CloseableHttpClient http = HttpClients.custom().setConnectionManager(bhcm).setDefaultRequestConfig(rc).build();
			    
			CloseableHttpResponse httpResp = http.execute(post);
			
			BufferedReader in = new BufferedReader(new InputStreamReader(httpResp.getEntity().getContent()));
			
			StringBuffer token = new StringBuffer();
			
			
			String line = null;
			while ((line = in.readLine()) != null) {
				token.append(line);
			}
			
			
			
			httpResp.close();
			bhcm.close();
			
			Gson gson = new Gson();
			
			Map tokenNVP = com.cedarsoftware.util.io.JsonReader.jsonToMaps(token.toString());
			
			String accessToken;
			
			//Store the bearer token for use by Unison
			request.getSession().setAttribute(bearerTokenName, tokenNVP.get("access_token"));
			
			
			
			Map jwtNVP = null;
			LoadUserData loadUser = null;
			try {
				loadUser = (LoadUserData) Class.forName(userLookupClassName).newInstance();
				jwtNVP = loadUser.loadUserAttributesFromIdP(request, response, cfg, authParams, tokenNVP);
			} catch (Exception e) {
				throw new ServletException("Could not load user data",e);
			} 
			
			
			if (jwtNVP == null) {
				as.setSuccess(false);
			} else {
				if (! linkToDirectory) {
					loadUnlinkedUser(session, noMatchOU, uidAttr, act, jwtNVP,defaultObjectClass);
					
					as.setSuccess(true);

					
				} else {
					lookupUser(as, session, myvd, noMatchOU, uidAttr, lookupFilter, act, jwtNVP,defaultObjectClass);
				}
				
				
				String redirectToURL = request.getParameter("target");
				if (redirectToURL != null && ! redirectToURL.isEmpty()) {
					reqHolder.setURL(redirectToURL);
				}
			}
			
			
			
			
			
			
			
			holder.getConfig().getAuthManager().nextAuth(request, response,session,false);
			
			
			
			
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
			logger.info("Filter : '" + filter + "'");
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
				
				
				Iterator<LDAPAttribute> it = entry.getAttributeSet().iterator();
				AuthInfo authInfo = new AuthInfo(entry.getDN(),(String) session.getAttribute(ProxyConstants.AUTH_MECH_NAME),act.getName(),act.getLevel());
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
		
		AuthInfo authInfo = new AuthInfo(dn.toString(),(String) session.getAttribute(ProxyConstants.AUTH_MECH_NAME),act.getName(),act.getLevel());
		((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).setAuthInfo(authInfo);
		
		for (Object o : jwtNVP.keySet()) {
			String s = (String) o;
			Attribute attr = new Attribute(s,jwtNVP.get(s).toString());
			authInfo.getAttribs().put(attr.getName(), attr);
			
		}
		
		authInfo.getAttribs().put("objectClass", new Attribute("objectClass",defaultObjectClass));
	}

	public void doPost(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		// TODO Auto-generated method stub

	}

	public void doPut(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		// TODO Auto-generated method stub

	}

	public void doHead(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		// TODO Auto-generated method stub

	}

	public void doOptions(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		// TODO Auto-generated method stub

	}

	public void doDelete(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		// TODO Auto-generated method stub

	}

}
