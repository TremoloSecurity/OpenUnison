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

import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.logging.log4j.Logger;
import org.checkerframework.checker.units.qual.A;
import org.joda.time.DateTime;
import org.joda.time.format.ISODateTimeFormat;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import com.google.gson.Gson;
import com.tremolosecurity.config.xml.ApplicationType;
import com.tremolosecurity.idp.providers.oidc.model.ExpiredRefreshToken;
import com.tremolosecurity.idp.providers.oidc.model.OidcSessionState;
import com.tremolosecurity.idp.providers.oidc.model.OidcSessionStore;
import com.tremolosecurity.idp.server.IDP;
import com.tremolosecurity.json.Token;
import com.tremolosecurity.log.AccessLog.AccessEvent;
import com.tremolosecurity.openunison.OpenUnisonConstants;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.mapping.MapIdentity;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;

public class K8sSessionStore implements OidcSessionStore {
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(K8sSessionStore.class.getName());
	
	String k8sTarget;
	String nameSpace;
	
	int refreshTokenGracePeriodMillis;
	HashMap<String, HashMap<String, Attribute>> trustCfg;
	
	private Gson gson;

	private String idpName;
	
	private String apiVersion;
	

	@Override
	public void init(String idpName, ServletContext ctx, HashMap<String, Attribute> init,
			HashMap<String, HashMap<String, Attribute>> trustCfg, MapIdentity mapper) throws Exception {
		
		this.k8sTarget = init.get("k8sTarget").getValues().get(0);
		this.nameSpace = init.get("k8sNameSpace").getValues().get(0);
		
		if (init.containsKey("refreshTokenGraceMillis")) {
			this.refreshTokenGracePeriodMillis = Integer.parseInt(init.get("refreshTokenGraceMillis").getValues().get(0));
		} else {
			this.refreshTokenGracePeriodMillis = 0;
		}
		
		this.trustCfg = trustCfg;
		this.idpName = idpName;
		this.gson = new Gson();
		this.apiVersion = null;

	}
	
	private synchronized String getApiVersion() {
		if (this.apiVersion != null) {
			return this.apiVersion;
		} else {
			int versionNumber = 1;
			boolean found = false;
			while (! found) {
				try {
					OpenShiftTarget target = (OpenShiftTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(this.k8sTarget).getProvider();
					HttpCon http = null;
					try {
						http = target.createClient();
						if (! target.isObjectExistsByPath(target.getAuthToken(), http, String.format("/apis/openunison.tremolo.io/v%s/namespaces/%s/oidc-sessions",versionNumber,this.nameSpace))) {
							versionNumber--;
							found = true;
						} else {
							versionNumber++;
						}
					} finally {
						if (http != null) {
							try {
								http.getHttp().close();
							} catch (Throwable t) {
								// doesnt matter
							}
							
							http.getBcm().close();
						}
					}
				} catch (Throwable e) {
					logger.warn("Could determine version type",e);
					return "v1";
				}
			}
			
			this.apiVersion = String.format("v%s",versionNumber);
			return this.apiVersion;
		}
	}

	@Override
	public void saveUserSession(OidcSessionState session) throws Exception {
		String sessionIdName = new StringBuilder().append("x").append(session.getSessionID()).append("x").toString();
		
		
		HashMap<String,Object> createObject = new HashMap<String,Object>();
		createObject.put("apiVersion", String.format("openunison.tremolo.io/%s",this.getApiVersion()));
		createObject.put("kind","OidcSession");
		HashMap<String,Object> metaData = new HashMap<String,Object>();
		createObject.put("metadata", metaData);
		metaData.put("name", sessionIdName);
		metaData.put("namespace",this.nameSpace);
		
		HashMap<String,Object> labels = new HashMap<String,Object>();
		metaData.put("labels",labels);
		labels.put("tremolo.io/user-dn", DigestUtils.sha1Hex(session.getUserDN()));
		
		HashMap<String,Object> spec = new HashMap<String,Object>();
		createObject.put("spec", spec);
		
		spec.put("session_id", session.getSessionID());
		spec.put("client_id",session.getClientID());
		spec.put("encrypted_id_token", session.getEncryptedIdToken());
		spec.put("encrypted_access_token",session.getEncryptedAccessToken());
		spec.put("user_dn", session.getUserDN());
		spec.put("refresh_token",session.getRefreshToken());
		
		if (! this.getApiVersion().equals("v1")) {
			storeExpiredTokens(session, spec);
		}
		
		
		
		spec.put("expires",ISODateTimeFormat.dateTime().print(session.getExpires()));
		
		
		OpenShiftTarget k8s = null;
		try {
			k8s = (OpenShiftTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(this.k8sTarget).getProvider();
		} catch (ProvisioningException e1) {
			logger.error("Could not retrieve kubernetes target",e1);
			throw new ProvisioningException("Could not connect to kubernetes",e1);
		}
		
		String url = new StringBuilder().append("/apis/openunison.tremolo.io/").append(this.getApiVersion()).append("/namespaces/").append(this.nameSpace).append("/oidc-sessions").toString();
		
		try {
			HttpCon con = k8s.createClient();
			
			try {
				String jsonReq = this.gson.toJson(createObject);
				String jsonResp = k8s.callWSPost(k8s.getAuthToken(), con, url,jsonReq);
				if (logger.isDebugEnabled()) {
					logger.debug("json response from creating object : " + jsonResp);
				}
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
	
	private Map<String,Attribute> findTrustByClientId(String clientid) {
		
		for (String trustname : this.trustCfg.keySet()) {
			
			Map<String,Attribute> trust = this.trustCfg.get(trustname);
			
			Attribute clientidAttr = trust.get("clientID");
			
			if (clientidAttr != null) {
				String cidval = clientidAttr.getValues().get(0);
				if (cidval.equals(clientid)) {
					return trust;
				}
			}
			
			
		}
		
		return null;
	}

	private void storeExpiredTokens(OidcSessionState session, Map<String, Object> spec) {
		
		String clientid = session.getClientID();
		Map<String,Attribute> trust = this.findTrustByClientId(clientid);
		
		if (trust == null) {
			logger.warn(String.format("Could not find trust %s, not storing expired tokens", clientid));
			return;
		}
		
		Attribute codeTokenCfg = trust.get("codeLastMileKeyName");
		
		if (codeTokenCfg == null) {
			logger.warn(String.format("Trust %s does not have a codeLastMileKeyName, not storing expired tokens", clientid));
			return;
		}
		
		String codeTokenKeyName = codeTokenCfg.getValues().get(0);
		
		
		JSONArray expiredTokens = new JSONArray();
		
		
		
		for (ExpiredRefreshToken expToken : session.getExpiredTokens()) {
			if (expToken.isStillInGracePeriod(this.refreshTokenGracePeriodMillis)) {
				expiredTokens.add(expToken.toJSONObject());
			}
		}
		
		
		
		try {
			spec.put("expired_tokens", this.encryptToken(codeTokenKeyName, gson, expiredTokens.toString()));
			//spec.put("expired_tokens", expiredTokens.toString());
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException | IOException e) {
			logger.warn(String.format("Could not encrypt expired tokens for %s, trust %s",this.idpName,clientid),e);
		}
	}
	
	private String encryptToken(String codeTokenKeyName, Gson gson, String data)
			throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException, IOException {
		byte[] bjson = data.getBytes("UTF-8");
		
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, GlobalEntries.getGlobalEntries().getConfigManager().getSecretKey(codeTokenKeyName));
		
		byte[] encJson = cipher.doFinal(bjson);
		String base64d = new String(org.bouncycastle.util.encoders.Base64.encode(encJson));
		
		Token token = new Token();
		token.setEncryptedRequest(base64d);
		token.setIv(new String(org.bouncycastle.util.encoders.Base64.encode(cipher.getIV())));
		
		
		byte[] bxml = gson.toJson(token).getBytes("UTF-8");

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		
		DeflaterOutputStream compressor  = new DeflaterOutputStream(baos,new Deflater(Deflater.BEST_COMPRESSION,true));
		
		compressor.write(bxml);
		compressor.flush();
		compressor.close();
		
		
		
		String b64 = new String( org.bouncycastle.util.encoders.Base64.encode(baos.toByteArray()));
		return b64;
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
		
		String url = new StringBuilder().append("/apis/openunison.tremolo.io/v2/namespaces/").append(this.nameSpace).append("/oidc-sessions/").append(sessionIdName).toString();
		
		try {
			HttpCon con = k8s.createClient();
			
			try {
				
				String jsonResp = k8s.callWSDelete(k8s.getAuthToken(), con, url);
				
				if (logger.isDebugEnabled()) {
					logger.debug("json response from deleting object : " + jsonResp);
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
		
		String url = new StringBuilder().append("/apis/openunison.tremolo.io/").append(this.getApiVersion()).append("/namespaces/").append(this.nameSpace).append("/oidc-sessions/").append(sessionIdName).toString();
		
		try {
			HttpCon con = k8s.createClient();
			
			try {
				
				String jsonResp = k8s.callWS(k8s.getAuthToken(), con, url);
				if (logger.isDebugEnabled()) {
					logger.debug("json response from deleting object : " + jsonResp);
				}
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

				
				String clientid = session.getClientID();
				Map<String,Attribute> trust = this.findTrustByClientId(clientid);
				
				if (trust == null) {
					logger.warn(String.format("Could not find trust %s, not loading expired tokens", clientid));
					return session;
				}
				
				Attribute codeTokenCfg = trust.get("codeLastMileKeyName");
				
				if (codeTokenCfg == null) {
					logger.warn(String.format("Trust %s does not have a codeLastMileKeyName, not loading expired tokens", clientid));
					return session;
				}
				
				String codeTokenKeyName = codeTokenCfg.getValues().get(0);
				
				String expiredTokensEncrypted = (String) spec.get("expired_tokens");
				
				if (expiredTokensEncrypted != null) {
					String expiredJson = this.decryptToken(codeTokenKeyName, gson, expiredTokensEncrypted);
					JSONArray expiredTokens = (JSONArray) new JSONParser().parse(expiredJson);
					for (Object obj : expiredTokens) {
						ExpiredRefreshToken token = new ExpiredRefreshToken((JSONObject) obj);
						if (token.isStillInGracePeriod(this.refreshTokenGracePeriodMillis)) {
							session.getExpiredTokens().add(token);
						}
						
					}
				}
				
				
				
				
					
				
				
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
	
	
	
	private String inflate(String saml) throws Exception {
		byte[] compressedData = org.bouncycastle.util.encoders.Base64.decode(saml);
		ByteArrayInputStream bin = new ByteArrayInputStream(compressedData);
		
		InflaterInputStream decompressor  = new InflaterInputStream(bin,new Inflater(true));
		//decompressor.setInput(compressedData);
		
		// Create an expandable byte array to hold the decompressed data
		ByteArrayOutputStream bos = new ByteArrayOutputStream(compressedData.length);
		
		// Decompress the data
		byte[] buf = new byte[1024];
		int len;
		while ((len = decompressor.read(buf)) > 0) {
		    
		        
		        bos.write(buf, 0, len);
		    
		}
		try {
		    bos.close();
		} catch (IOException e) {
		}

		// Get the decompressed data
		byte[] decompressedData = bos.toByteArray();
		
		String decoded = new String(decompressedData);
		
		return decoded;
	}
	
	
	private String decryptToken(String codeTokenKeyName, Gson gson, String encrypted) throws Exception {
		String inflated = this.inflate(encrypted);
		Token token = gson.fromJson(inflated, Token.class);
		
		byte[] iv = org.bouncycastle.util.encoders.Base64.decode(token.getIv());
		IvParameterSpec spec =  new IvParameterSpec(iv);
		
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, GlobalEntries.getGlobalEntries().getConfigManager().getSecretKey(codeTokenKeyName),spec);
		
		byte[] decBytes = org.bouncycastle.util.encoders.Base64.decode(token.getEncryptedRequest());
		
		return new String(cipher.doFinal(decBytes));
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
		
		String url = new StringBuilder().append("/apis/openunison.tremolo.io/").append(this.getApiVersion()).append("/namespaces/").append(this.nameSpace).append("/oidc-sessions/").append(sessionIdName).toString();
		
		try {
			HttpCon con = k8s.createClient();
			
			try {
				
				String jsonResp = k8s.callWS(k8s.getAuthToken(), con, url);
				if (logger.isDebugEnabled()) {
					logger.debug("json response from deleting object : " + jsonResp);
				}
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
				storeExpiredTokens(session, spec);
				
				
				jsonResp = k8s.callWSPatchJson(k8s.getAuthToken(), con, url,gson.toJson(obj));
				if (logger.isDebugEnabled()) {
					logger.debug("json response from patch : '" + jsonResp + "'");
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
	public void cleanOldSessions() throws Exception {
		OpenShiftTarget k8s = null;
		try {
			k8s = (OpenShiftTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(this.k8sTarget).getProvider();
		} catch (ProvisioningException e1) {
			logger.error("Could not retrieve kubernetes target",e1);
			throw new ProvisioningException("Could not connect to kubernetes",e1);
		}
		
		String url = new StringBuilder().append("/apis/openunison.tremolo.io/").append(this.getApiVersion()).append("/namespaces/").append(this.nameSpace).append("/oidc-sessions").toString();
		
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

	@Override
	public void deleteAllSessions(String sessionId) throws Exception {



		String sessionIdName = new StringBuilder().append("x").append(sessionId).append("x").toString();
		
		OpenShiftTarget k8s = null;
		try {
			k8s = (OpenShiftTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(this.k8sTarget).getProvider();
		} catch (ProvisioningException e1) {
			logger.error("Could not retrieve kubernetes target",e1);
			throw new ProvisioningException("Could not connect to kubernetes",e1);
		}
		
		String url = new StringBuilder().append("/apis/openunison.tremolo.io/").append(this.getApiVersion()).append("/namespaces/").append(this.nameSpace).append("/oidc-sessions/").append(sessionIdName).toString();
		
		try {
			HttpCon con = k8s.createClient();
			
			
			
			try {
				
				String jsonResp = k8s.callWS(k8s.getAuthToken(), con, url);
				JSONObject root = (JSONObject) new JSONParser().parse(jsonResp);
				
				if (root.containsKey("kind") && root.get("kind").equals("Status") && ((Long) root.get("code")) == 404) {
					logger.warn(new StringBuilder().append("Session ID ").append(sessionId).append(" does not exist"));
					return;
				}
				
				JSONObject metadata = (JSONObject) root.get("metadata");
				
				JSONObject labels = (JSONObject) metadata.get("labels");
				
				String dnHash = (String) labels.get("tremolo.io/user-dn");
				
				url = new StringBuilder().append("/apis/openunison.tremolo.io/").append(this.getApiVersion()).append("/namespaces/").append(this.nameSpace).append("/oidc-sessions?labelSelector=tremolo.io%2Fuser-dn%3D").append(dnHash).toString();
				
				
				jsonResp = k8s.callWSDelete(k8s.getAuthToken(), con, url);
				
				if (logger.isDebugEnabled()) {
					logger.debug("json response from deleting object : " + jsonResp);
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
		

}
