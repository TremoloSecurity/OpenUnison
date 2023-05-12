/*******************************************************************************
* Copyright 2019 Tremolo Security, Inc.
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
package com.tremolosecurity.proxy.auth.oauth2;

import static org.apache.directory.ldap.client.api.search.FilterBuilder.equal;

import java.io.IOException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.http.Header;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.message.BasicHeader;
import org.apache.http.util.EntityUtils;
import org.joda.time.DateTime;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.auth.RequestHolder;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.myvd.MyVDConnection;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;


public class OAuth2JWT extends OAuth2Bearer {
	
	static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(OAuth2JWT.class.getName());

	static HashMap<String,List<PublicKey>> keyCache = new HashMap<String,List<PublicKey>>();
	
	public HttpCon createClient() throws Exception {
		ArrayList<Header> defheaders = new ArrayList<Header>();
		defheaders.add(new BasicHeader("X-Csrf-Token", "1"));

		BasicHttpClientConnectionManager bhcm = new BasicHttpClientConnectionManager(
				GlobalEntries.getGlobalEntries().getConfigManager().getHttpClientSocketRegistry());

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
	public void processToken(HttpServletRequest request, HttpServletResponse response, AuthStep as, HttpSession session,
			HashMap<String, Attribute> authParams, AuthChainType act, String realmName, String scope, ConfigManager cfg,
			String lmToken) throws ServletException, IOException {
		
		String issuer = authParams.get("issuer").getValues().get(0);
		HashSet<String> audiences = new HashSet<String>();
		if (authParams.get("audience") == null) {
			logger.warn("No audience configuration, all requests will fail");
		} else {
			audiences.addAll(authParams.get("audience").getValues());
		}
		
		
		String fromWellKnown = authParams.get("fromWellKnown") != null ? authParams.get("fromWellKnown").getValues().get(0) : "false";
		
		boolean useWellKnown = fromWellKnown.equalsIgnoreCase("true");
		
		List<PublicKey> pks = null;
		
		if (useWellKnown) {
			pks = keyCache.get(issuer);
			if (pks == null) {
				StringBuilder sb = new StringBuilder();
				sb.append(issuer);
				if (! issuer.endsWith("/")) {
					sb.append("/");
					
				}
				sb.append(".well-known/openid-configuration");
				
				String wellKnownURL = sb.toString();
				HttpCon http = null;
				try {
					http = this.createClient();
					HttpGet get = new HttpGet(wellKnownURL);
					CloseableHttpResponse resp = http.getHttp().execute(get);
					String json = EntityUtils.toString(resp.getEntity());
					resp.close();
					JSONParser parser = new JSONParser();
					JSONObject root = (JSONObject) parser.parse(json);
					String jwksUrl = (String) root.get("jwks_uri");
					
					get = new HttpGet(jwksUrl);
					resp = http.getHttp().execute(get);
					json = EntityUtils.toString(resp.getEntity());
					resp.close();
					
					
					
					pks = new ArrayList<PublicKey>();
					JsonWebKeySet jks = new JsonWebKeySet(json);
					for (JsonWebKey j : jks.getJsonWebKeys()) {
						if (j.getUse().equalsIgnoreCase("sig")) {
							pks.add((PublicKey)j.getKey());
						}
					}
					
					
					if (pks.size() == 0) {
						throw new ServletException("No key found");
					}
					
					
					
					keyCache.put(issuer, pks);
					
					
					
					
				} catch (Exception e) {
					throw new ServletException("Could not get oidc certs",e);
				} finally {
					if (http != null) {
						http.getHttp().close();
						http.getBcm().close();
					}
				}
				
			}
			
		} else {
			String validationKey = authParams.get("validationKey").getValues().get(0);
			pks = new ArrayList<PublicKey>();
			
			pks.add( cfg.getCertificate(validationKey).getPublicKey());
		}
		
		
		
		boolean linkToDirectory = Boolean.parseBoolean(authParams.get("linkToDirectory").getValues().get(0));
		String noMatchOU = authParams.get("noMatchOU").getValues().get(0);
		String uidAttr = authParams.get("uidAttr").getValues().get(0);
		String lookupFilter = authParams.get("lookupFilter").getValues().get(0);
		
		
		String defaultObjectClass = authParams.get("defaultObjectClass").getValues().get(0);
		
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		RequestHolder reqHolder = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
		
		
		JsonWebSignature jws = new JsonWebSignature();
		try {
			boolean sigVerified = false;
			jws.setCompactSerialization(lmToken);
			
			for (PublicKey pk : pks) {
				jws.setKey(pk);
				if (jws.verifySignature()) {
					sigVerified = true;
					break;
				}
			}
				
			
			if (! sigVerified) {
				as.setExecuted(true);
				as.setSuccess(false);
				
				logger.warn("Could not verify signature");
				
				cfg.getAuthManager().nextAuth(request, response,request.getSession(),false);
				super.sendFail(response, realmName, scope, null, null);
				return;
			}
			
			String json = jws.getPayload();
			JSONObject obj = (JSONObject) new JSONParser().parse(json);
			long exp = ((Long)obj.get("exp")) * 1000L;
			long nbf = ((Long)obj.get("nbf")) * 1000L;
			
			if (new DateTime(exp).isBeforeNow()) {
				as.setExecuted(true);
				as.setSuccess(false);
				
				logger.warn("JWT not yet valid");
				
				cfg.getAuthManager().nextAuth(request, response,request.getSession(),false);
				super.sendFail(response, realmName, scope, null, null);
				return;
			}
			
			if (new DateTime(nbf).isAfterNow()) {
				as.setExecuted(true);
				as.setSuccess(false);
				
				logger.warn("JWT expired");
				
				cfg.getAuthManager().nextAuth(request, response,request.getSession(),false);
				super.sendFail(response, realmName, scope, null, null);
				return;
			}
			
			if (! ((String) obj.get("iss")).equals(issuer)) {
				as.setExecuted(true);
				as.setSuccess(false);
				
				logger.warn("JWT invalid issuer");
				
				cfg.getAuthManager().nextAuth(request, response,request.getSession(),false);
				super.sendFail(response, realmName, scope, null, null);
				return;
			}
			
			Object aud = obj.get("aud");
			
			if (aud == null ) {
				logger.warn("JWT has no aud");
				as.setExecuted(true);
				as.setSuccess(false);
				cfg.getAuthManager().nextAuth(request, response,request.getSession(),false);
				super.sendFail(response, realmName, scope, null, null);
				return;
			} else if (aud instanceof JSONArray) {
				JSONArray auds = (JSONArray) aud;
				boolean found = false;
				for (Object audVal : auds) {
					if (audiences.contains((String) audVal)) {
						found = true;
					}
				}
				if (! found) {
					as.setExecuted(true);
					as.setSuccess(false);
					logger.warn("Invalid audience");
					cfg.getAuthManager().nextAuth(request, response,request.getSession(),false);
					super.sendFail(response, realmName, scope, null, null);
					return;
				}
			} else {
				if (! audiences.contains((String) aud)) {
					as.setExecuted(true);
					as.setSuccess(false);
					
					logger.warn("Invalid audience");
					
					cfg.getAuthManager().nextAuth(request, response,request.getSession(),false);
					super.sendFail(response, realmName, scope, null, null);
					return;
				}
			}
			
			if (! linkToDirectory) {
				loadUnlinkedUser(session, noMatchOU, uidAttr, act, obj,defaultObjectClass);
				
				as.setSuccess(true);

				
			} else {
				lookupUser(as, session, cfg.getMyVD(), noMatchOU, uidAttr, lookupFilter, act, obj,defaultObjectClass);
			}
			
			
			String redirectToURL = request.getParameter("target");
			if (redirectToURL != null && ! redirectToURL.isEmpty()) {
				reqHolder.setURL(redirectToURL);
			}
			
			as.setExecuted(true);
			as.setSuccess(true);
			
			cfg.getAuthManager().nextAuth(request, response,request.getSession(),false);
		} catch (JoseException | ParseException e) {
			throw new ServletException("Could not process JWT",e);
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
			
			Attribute attr;
			
			Object oAttr = jwtNVP.get(s);
			
			if (logger.isDebugEnabled()) {
				logger.debug(s + " type - '" + oAttr.getClass().getName() + "'");
			}
			
			if (oAttr instanceof JSONArray) {
				attr = new Attribute(s);
				for (Object ox : ((JSONArray) oAttr)) {
					attr.getValues().add((String) ox);
				}
			} else {
				attr = new Attribute(s,oAttr.toString());
			}
			
			 
			authInfo.getAttribs().put(attr.getName(), attr);
			
		}
		
		authInfo.getAttribs().put("objectClass", new Attribute("objectClass",defaultObjectClass));
	}

}
