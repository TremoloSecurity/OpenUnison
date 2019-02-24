/*******************************************************************************
 * Copyright 2018 Tremolo Security, Inc.
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
package com.tremolosecurity.oidc.k8s;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletContext;

import org.apache.logging.log4j.Logger;
import org.joda.time.DateTime;
import org.joda.time.format.ISODateTimeFormat;

import com.google.gson.Gson;
import com.tremolosecurity.idp.providers.oidc.model.OidcSessionState;
import com.tremolosecurity.idp.providers.oidc.model.OidcSessionStore;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.mapping.MapIdentity;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;

public class K8sSessionStore implements OidcSessionStore {
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(K8sSessionStore.class.getName());
	
	String k8sTarget;
	String nameSpace;
	
	private Gson gson;

	@Override
	public void init(String idpName, ServletContext ctx, HashMap<String, Attribute> init,
			HashMap<String, HashMap<String, Attribute>> trustCfg, MapIdentity mapper) throws Exception {
		this.k8sTarget = init.get("k8sTarget").getValues().get(0);
		this.nameSpace = init.get("k8sNameSpace").getValues().get(0);
		this.gson = new Gson();

	}

	@Override
	public void saveUserSession(OidcSessionState session) throws Exception {
		String sessionIdName = new StringBuilder().append("x").append(session.getSessionID()).append("x").toString();
		
		
		HashMap<String,Object> createObject = new HashMap<String,Object>();
		createObject.put("apiVersion", "openunison.tremolo.io/v1");
		createObject.put("kind","OidcSession");
		HashMap<String,Object> metaData = new HashMap<String,Object>();
		createObject.put("metadata", metaData);
		metaData.put("name", sessionIdName);
		metaData.put("namespace",this.nameSpace);
		
		HashMap<String,Object> spec = new HashMap<String,Object>();
		createObject.put("spec", spec);
		
		spec.put("session_id", session.getSessionID());
		spec.put("client_id",session.getClientID());
		spec.put("encrypted_id_token", session.getEncryptedIdToken());
		spec.put("encrypted_access_token",session.getEncryptedAccessToken());
		spec.put("user_dn", session.getUserDN());
		spec.put("refresh_token",session.getRefreshToken());
		
		
		
		spec.put("expires",ISODateTimeFormat.dateTime().print(session.getExpires()));
		
		
		OpenShiftTarget k8s = null;
		try {
			k8s = (OpenShiftTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(this.k8sTarget).getProvider();
		} catch (ProvisioningException e1) {
			logger.error("Could not retrieve kubernetes target",e1);
			throw new ProvisioningException("Could not connect to kubernetes",e1);
		}
		
		String url = new StringBuilder().append("/apis/openunison.tremolo.io/v1/namespaces/").append(this.nameSpace).append("/oidc-sessions").toString();
		
		try {
			HttpCon con = k8s.createClient();
			
			try {
				String jsonReq = this.gson.toJson(createObject);
				String jsonResp = k8s.callWSPost(k8s.getAuthToken(), con, url,jsonReq);
				
				logger.info("json response from creating object : " + jsonResp);
				//TODO do something?
			} finally {
				con.getHttp().close();
				con.getBcm().close();
			}
		} catch (Exception e) {
			logger.error("Could not search k8s",e);
			throw new Exception("Error searching kubernetes",e);
			
		}

	}

	@Override
	public void deleteSession(String sessionId) throws Exception {
		String sessionIdName = new StringBuilder().append("x").append(sessionId).append("x").toString();
		
		OpenShiftTarget k8s = null;
		try {
			k8s = (OpenShiftTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(this.k8sTarget).getProvider();
		} catch (ProvisioningException e1) {
			logger.error("Could not retrieve kubernetes target",e1);
			throw new ProvisioningException("Could not connect to kubernetes",e1);
		}
		
		String url = new StringBuilder().append("/apis/openunison.tremolo.io/v1/namespaces/").append(this.nameSpace).append("/oidc-sessions/").append(sessionIdName).toString();
		
		try {
			HttpCon con = k8s.createClient();
			
			try {
				
				String jsonResp = k8s.callWSDelete(k8s.getAuthToken(), con, url);
				
				if (logger.isDebugEnabled()) {
					logger.info("json response from deleting object : " + jsonResp);
				}
				
			} finally {
				con.getHttp().close();
				con.getBcm().close();
			}
		} catch (Exception e) {
			logger.error("Could not search k8s",e);
			throw new Exception("Error searching kubernetes",e);
			
		}

	}

	@Override
	public OidcSessionState getSession(String sessionId) throws Exception {
		String sessionIdName = new StringBuilder().append("x").append(sessionId).append("x").toString();
		
		OpenShiftTarget k8s = null;
		try {
			k8s = (OpenShiftTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(this.k8sTarget).getProvider();
		} catch (ProvisioningException e1) {
			logger.error("Could not retrieve kubernetes target",e1);
			throw new ProvisioningException("Could not connect to kubernetes",e1);
		}
		
		String url = new StringBuilder().append("/apis/openunison.tremolo.io/v1/namespaces/").append(this.nameSpace).append("/oidc-sessions/").append(sessionIdName).toString();
		
		try {
			HttpCon con = k8s.createClient();
			
			try {
				
				String jsonResp = k8s.callWS(k8s.getAuthToken(), con, url);
				
				logger.info("json response from deleting object : " + jsonResp);
				Map ret = gson.fromJson(jsonResp, Map.class);
				Map spec = (Map) ret.get("spec");
				
				if (spec == null) {
					return null;
				}
				
				OidcSessionState session = new OidcSessionState();
				session.setSessionID(spec.get("session_id").toString());
				session.setClientID(spec.get("client_id").toString());
				session.setEncryptedAccessToken(spec.get("encrypted_access_token").toString());
				session.setEncryptedIdToken(spec.get("encrypted_id_token").toString());
				session.setRefreshToken(spec.get("refresh_token").toString());
				session.setUserDN(spec.get("user_dn").toString());
				session.setExpires(ISODateTimeFormat.dateTime().parseDateTime(spec.get("expires").toString()));

				return session;
			} finally {
				con.getHttp().close();
				con.getBcm().close();
			}
		} catch (Exception e) {
			logger.error("Could not search k8s",e);
			throw new Exception("Error searching kubernetes",e);
			
		}
	}

	@Override
	public void resetSession(OidcSessionState session) throws Exception {
		String sessionIdName = new StringBuilder().append("x").append(session.getSessionID()).append("x").toString();
		
		OpenShiftTarget k8s = null;
		try {
			k8s = (OpenShiftTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(this.k8sTarget).getProvider();
		} catch (ProvisioningException e1) {
			logger.error("Could not retrieve kubernetes target",e1);
			throw new ProvisioningException("Could not connect to kubernetes",e1);
		}
		
		String url = new StringBuilder().append("/apis/openunison.tremolo.io/v1/namespaces/").append(this.nameSpace).append("/oidc-sessions/").append(sessionIdName).toString();
		
		try {
			HttpCon con = k8s.createClient();
			
			try {
				
				String jsonResp = k8s.callWS(k8s.getAuthToken(), con, url);
				
				logger.info("json response from deleting object : " + jsonResp);
				Map ret = gson.fromJson(jsonResp, Map.class);
				Map obj = new HashMap();
				
				Map spec = (Map) ret.get("spec");
				obj.put("spec", spec);
				
				if (spec == null) {
					return;
				}
				
				spec.put("encrypted_id_token", session.getEncryptedIdToken());
				spec.put("encrypted_access_token",session.getEncryptedAccessToken());
				spec.put("refresh_token",session.getRefreshToken());
				spec.put("expires",ISODateTimeFormat.dateTime().print(session.getExpires()));
				
				
				
				jsonResp = k8s.callWSPatchJson(k8s.getAuthToken(), con, url,gson.toJson(obj));
				logger.info("json response from patch : '" + jsonResp + "'");
			} finally {
				con.getHttp().close();
				con.getBcm().close();
			}
		} catch (Exception e) {
			logger.error("Could not search k8s",e);
			throw new Exception("Error searching kubernetes",e);
			
		}

	}

	@Override
	public void cleanOldSessions() throws Exception {
		OpenShiftTarget k8s = null;
		try {
			k8s = (OpenShiftTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(this.k8sTarget).getProvider();
		} catch (ProvisioningException e1) {
			logger.error("Could not retrieve kubernetes target",e1);
			throw new ProvisioningException("Could not connect to kubernetes",e1);
		}
		
		String url = new StringBuilder().append("/apis/openunison.tremolo.io/v1/namespaces/").append(this.nameSpace).append("/oidc-sessions").toString();
		
		try {
			HttpCon con = k8s.createClient();
			
			try {
				
				String jsonResp = k8s.callWS(k8s.getAuthToken(), con, url);
				Map ret = gson.fromJson(jsonResp, Map.class);
				List items = (List) ret.get("items");
				for (Object o : items) {
					Map session = (Map) o;
					Map spec = (Map) session.get("spec");
					String sessionid = (String) spec.get("session_id");
					DateTime expires = ISODateTimeFormat.dateTime().parseDateTime((String) spec.get("expires"));
					
					if (expires.isBeforeNow()) {
						this.deleteSession(sessionid);
					}
				}
				
				
			} finally {
				con.getHttp().close();
				con.getBcm().close();
			}
		} catch (Exception e) {
			logger.error("Could not search k8s",e);
			throw new Exception("Error searching kubernetes",e);
			
		}
				

	}

	@Override
	public void shutdown() throws Exception {
		

	}

}
