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
package com.tremolosecurity.proxy.auth;

import static org.apache.directory.ldap.client.api.search.FilterBuilder.equal;

import java.io.IOException;
import java.util.*;

import com.novell.ldap.util.ByteArray;
import com.tremolosecurity.proxy.TremoloHttpSession;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.joda.time.DateTime;
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
import com.tremolosecurity.proxy.auth.oauth2.OAuth2Bearer;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.myvd.MyVDConnection;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;


public class OAuth2K8sServiceAccount extends OAuth2Bearer {
	
	static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(OAuth2K8sServiceAccount.class.getName());

	@Override
	public void processToken(HttpServletRequest request, HttpServletResponse response, AuthStep as, HttpSession session,
			HashMap<String, Attribute> authParams, AuthChainType act, String realmName, String scope, ConfigManager cfg,
			String lmToken) throws ServletException, IOException {
		
		
		String k8sTarget = authParams.get("k8sTarget").getValues().get(0);
		
		boolean linkToDirectory = Boolean.parseBoolean(authParams.get("linkToDirectory").getValues().get(0));
		String noMatchOU = authParams.get("noMatchOU").getValues().get(0);
		String uidAttr = authParams.get("uidAttr").getValues().get(0);
		String lookupFilter = authParams.get("lookupFilter").getValues().get(0);
		
		
		String defaultObjectClass = authParams.get("defaultObjectClass").getValues().get(0);
		
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		RequestHolder reqHolder = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
		
		
		
		JSONObject root = new JSONObject();
		root.put("kind", "TokenReview");
		root.put("apiVersion","authentication.k8s.io/v1");
		root.put("spec", new JSONObject());
		((JSONObject) root.get("spec")).put("token", lmToken);
		
		String json = root.toJSONString();
		
		OpenShiftTarget target = null;
		HttpCon con = null;
		
		try {
			target = (OpenShiftTarget) cfg.getProvisioningEngine().getTarget(k8sTarget).getProvider();
			con = target.createClient();
			String respJSON = target.callWSPost(target.getAuthToken(), con, "/apis/authentication.k8s.io/v1/tokenreviews", json);
			
			if (logger.isDebugEnabled()) {
				logger.debug("JSON - " + respJSON);
			}
			
			JSONParser parser = new JSONParser();
			JSONObject resp = (JSONObject) parser.parse(respJSON);
			JSONObject status = (JSONObject) resp.get("status");
			
			if (status.get("error") != null) {
				logger.error("Could not validate token : " + status.get("error"));
				as.setExecuted(true);
				as.setSuccess(false);
				
				cfg.getAuthManager().nextAuth(request, response,request.getSession(),false);
				super.sendFail(response, realmName, scope, null, null);
				return;
			} else {
				Boolean authenticated = (Boolean) status.get("authenticated");
				if (authenticated != null && authenticated) {
					JSONObject user = (JSONObject) status.get("user");
					
					if (! linkToDirectory) {
						loadUnlinkedUser(session, noMatchOU, uidAttr, act, user,defaultObjectClass);
						
						as.setSuccess(true);

						
					} else {
						lookupUser(as, session, cfg.getMyVD(), noMatchOU, uidAttr, lookupFilter, act, user,defaultObjectClass);
					}
					
					
					String redirectToURL = request.getParameter("target");
					if (redirectToURL != null && ! redirectToURL.isEmpty()) {
						reqHolder.setURL(redirectToURL);
					}
					
					as.setExecuted(true);
					as.setSuccess(true);
					
					cfg.getAuthManager().nextAuth(request, response,request.getSession(),false);
					
				} else {
					as.setExecuted(true);
					as.setSuccess(false);
					
					cfg.getAuthManager().nextAuth(request, response,request.getSession(),false);
					super.sendFail(response, realmName, scope, null, null);
					return;
				}
			}
		} catch (Exception e) {
			throw new ServletException("Could not validate token",e);
		} finally {
			con.getHttp().close();
			con.getBcm().close();
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
					LinkedList<ByteArray> vals = attrib.getAllValues();
					for (ByteArray val: vals) {
						attr.getValues().add(new String(val.getValue()));
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
		
		authInfo.getAttribs().put("sub", new Attribute("sub",uid));
		
		authInfo.getAttribs().put("objectClass", new Attribute("objectClass",defaultObjectClass));
	}

}
