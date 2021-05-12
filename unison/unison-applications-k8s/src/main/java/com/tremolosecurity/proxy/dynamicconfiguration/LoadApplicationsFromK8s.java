/*******************************************************************************
 * Copyright 2021 Tremolo Security, Inc.
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
package com.tremolosecurity.proxy.dynamicconfiguration;

import java.math.BigInteger;
import java.util.Map;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.ApplicationType;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.AuthLockoutType;
import com.tremolosecurity.config.xml.AuthMechParamType;
import com.tremolosecurity.config.xml.AuthMechType;
import com.tremolosecurity.config.xml.AzRuleType;
import com.tremolosecurity.config.xml.AzRulesType;
import com.tremolosecurity.config.xml.ConfigType;
import com.tremolosecurity.config.xml.CookieConfigType;
import com.tremolosecurity.config.xml.CustomAzRuleType;
import com.tremolosecurity.config.xml.FilterChainType;
import com.tremolosecurity.config.xml.FilterConfigType;
import com.tremolosecurity.config.xml.IdpMappingType;
import com.tremolosecurity.config.xml.IdpType;
import com.tremolosecurity.config.xml.MechanismType;
import com.tremolosecurity.config.xml.ParamListType;
import com.tremolosecurity.config.xml.ParamType;
import com.tremolosecurity.config.xml.ParamWithValueType;
import com.tremolosecurity.config.xml.ProvisionMappingType;
import com.tremolosecurity.config.xml.ResultGroupType;
import com.tremolosecurity.config.xml.ResultRefType;
import com.tremolosecurity.config.xml.ResultType;
import com.tremolosecurity.config.xml.TargetType;
import com.tremolosecurity.config.xml.TremoloType;
import com.tremolosecurity.config.xml.TrustType;
import com.tremolosecurity.config.xml.TrustsType;
import com.tremolosecurity.config.xml.UrlType;
import com.tremolosecurity.config.xml.UrlsType;
import com.tremolosecurity.k8s.watch.K8sWatchTarget;
import com.tremolosecurity.k8s.watch.K8sWatcher;
import com.tremolosecurity.openunison.util.config.OpenUnisonConfigLoader;
import com.tremolosecurity.provisioning.core.ProvisioningEngine;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.proxy.dynamicloaders.DynamicApplications;
import com.tremolosecurity.proxy.dynamicloaders.DynamicAuthChains;
import com.tremolosecurity.proxy.dynamicloaders.DynamicAuthMechs;
import com.tremolosecurity.proxy.dynamicloaders.DynamicAuthorizations;
import com.tremolosecurity.proxy.dynamicloaders.DynamicResultGroups;
import com.tremolosecurity.provisioning.targets.LoadTargetsFromK8s;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;

public class LoadApplicationsFromK8s  implements DynamicApplications, K8sWatchTarget {
static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(LoadApplicationsFromK8s.class.getName());
	
	K8sWatcher k8sWatch;
	
	TremoloType tremolo;

	private ProvisioningEngine provisioningEngine;
	private ConfigManager cfgMgr;
	
	
	public static ApplicationType createApplication (JSONObject item, String name) throws Exception {
		ApplicationType app = new ApplicationType();
		
		app.setName(name);
		
		JSONObject spec = (JSONObject) item.get("spec");
		
		app.setAzTimeoutMillis(getLongValue(spec.get("azTimeoutMillis"), 3000));
		app.setIsApp(getBoolValue(spec.get("isApp"), true));
		
		JSONArray urls = (JSONArray) spec.get("urls");
		app.setUrls(new UrlsType());
		
		for (Object o : urls) {
			JSONObject jsonUrl = (JSONObject) o;
			UrlType url = new UrlType();
			
			if (! app.isIsApp()) {
				createIdpOnUrl(jsonUrl, url);				
			}
			
			JSONArray hosts = (JSONArray) jsonUrl.get("hosts");
			for (Object x : hosts) {
				url.getHost().add((String) x);
			}
			
			JSONArray filters = (JSONArray) jsonUrl.get("filterChain");
			url.setFilterChain(new FilterChainType());
			
			if (filters != null) {
				for (Object x : filters) {
					JSONObject jsonFilter = (JSONObject) x; 
					FilterConfigType ft = new FilterConfigType();
					ft.setClazz((String) jsonFilter.get("className"));
					
					JSONObject params = (JSONObject) jsonFilter.get("params");
					if (params != null) {
						for (Object y : params.keySet()) {
							String paramName = (String) y;
							Object z = params.get(paramName);
							
							if (z instanceof String) {
								ParamWithValueType pt = new ParamWithValueType();
								pt.setName(paramName);
								pt.setValue((String)z);
								ft.getParam().add(pt);
							} else {
								JSONArray values = (JSONArray) z;
								
								for (Object w : values) {
									ParamWithValueType pt = new ParamWithValueType();
									pt.setName(paramName);
									pt.setValue((String) w);
									ft.getParam().add(pt);
								}
							}
						}
					}
					
					url.getFilterChain().getFilter().add(ft);
				}
			}
			
			
			JSONArray jsonAzRules = (JSONArray) jsonUrl.get("azRules");
			AzRulesType art = new AzRulesType();
			
			if (jsonAzRules != null) {
				for (Object x : jsonAzRules) {
					JSONObject jsonRule = (JSONObject) x;
					AzRuleType artx = new AzRuleType();
					artx.setScope((String)jsonRule.get("scope"));
					artx.setConstraint((String) jsonRule.get("constraint"));
					art.getRule().add(artx);
				}
			}
			
			url.setAzRules(art);
			
			url.setProxyTo((String) jsonUrl.get("proxyTo"));
			url.setUri((String)jsonUrl.get("uri"));
			url.setRegex(getBoolValue(jsonUrl.get("regex"), false));
			url.setAuthChain((String)jsonUrl.get("authChain"));
			url.setOverrideHost(getBoolValue(jsonUrl.get("overrideHost"),false));
			url.setOverrideReferer(getBoolValue(jsonUrl.get("overrideReferer"), false));
			
			
			JSONObject jsonResults = (JSONObject) jsonUrl.get("results");
			
			if (jsonResults != null) {
				ResultRefType rt = new ResultRefType();
				rt.setAuSuccess((String) jsonResults.get("auSuccess"));
				rt.setAzSuccess((String) jsonResults.get("azSuccess"));
				rt.setAuFail((String) jsonResults.get("auFail"));
				rt.setAzFail((String) jsonResults.get("azFail"));
				url.setResults(rt);
			}
			
			
			
			
			app.getUrls().getUrl().add(url);
			
			
			
		}
		
		JSONObject jsonCookie = (JSONObject) spec.get("cookieConfig");
		
		if (jsonCookie != null) {
			CookieConfigType cct = new CookieConfigType();
			cct.setSessionCookieName((String)jsonCookie.get("sessionCookieName"));
			cct.setDomain((String) jsonCookie.get("domain"));
			cct.setScope(getIntValue(jsonCookie.get("scope"),-1));
			cct.setLogoutURI((String) jsonCookie.get("logoutURI"));
			cct.setKeyAlias((String) jsonCookie.get("keyAlias"));
			cct.setTimeout(getIntValue(jsonCookie.get("timeout"), 0).intValue());
			cct.setSecure(getBoolValue(jsonCookie.get("secure"), false));
			cct.setHttpOnly(getBoolValue(jsonCookie.get("httpOnly"), false));
			cct.setSameSite((String)jsonCookie.get("sameSite"));
			cct.setCookiesEnabled(getBoolValue(jsonCookie.get("cookiesEnabled"), true));
			app.setCookieConfig(cct);
		}
		
		
		
		
		return app;
		
	}



	private static BigInteger getIntValue(Object object, int i) {
		if (object == null) {
			return BigInteger.valueOf(i);
		} else {
			return BigInteger.valueOf((Long)object);
		}
	}



	private static void createIdpOnUrl(JSONObject jsonUrl, UrlType url) {
		IdpType idp = new IdpType();
		JSONObject jsonIdp = (JSONObject) jsonUrl.get("idp");
		url.setIdp(idp);
		
		idp.setClassName((String)jsonIdp.get("className"));
		
		JSONObject params = (JSONObject) jsonIdp.get("params");
		if (params != null) {
			for (Object x : params.keySet()) {
				String paramName = (String) x;
				Object z = params.get(paramName);
				
				if (z instanceof String) {
					ParamType pt = new ParamType();
					pt.setName(paramName);
					pt.setValue((String)z);
					idp.getParams().add(pt);
				} else {
					JSONArray values = (JSONArray) z;
					
					for (Object y : values) {
						ParamType pt = new ParamType();
						pt.setName(paramName);
						pt.setValue((String) y);
						idp.getParams().add(pt);
					}
				}
			}
		}
		
		JSONObject mappings = (JSONObject) jsonIdp.get("mappings");
		if (mappings != null) {
			IdpMappingType idpMappingType = new IdpMappingType();
			idpMappingType.setStrict(getBoolValue(mappings.get("strict"), true));
			JSONArray jsonMap = (JSONArray) mappings.get("map");
			if (jsonMap != null) {
				for (Object x : jsonMap) {
					JSONObject map = (JSONObject)x;
					ProvisionMappingType pmt = new ProvisionMappingType();
					pmt.setTargetAttributeName((String)map.get("targetAttributeName"));
					pmt.setTargetAttributeSource((String) map.get("targetAttributeSource"));
					pmt.setSourceType((String) map.get("sourceType"));
					idpMappingType.getMapping().add(pmt);
				}
			}
			
			idp.setMappings(idpMappingType);
		}
		
		JSONArray jsonTrusts = (JSONArray) jsonIdp.get("trusts");
		if (jsonTrusts != null) {
			TrustsType tt = new TrustsType();
			
			for (Object o : jsonTrusts) {
				JSONObject jsonTrust = (JSONObject) o;
				TrustType trust = new TrustType();
				trust.setName((String) jsonTrust.get("name"));
				
				params = (JSONObject) jsonTrust.get("params");
				if (params != null) {
					for (Object x : params.keySet()) {
						String paramName = (String) x;
						Object z = params.get(paramName);
						
						if (z instanceof String) {
							ParamType pt = new ParamType();
							pt.setName(paramName);
							pt.setValue((String)z);
							trust.getParam().add(pt);
						} else {
							JSONArray values = (JSONArray) z;
							
							for (Object y : values) {
								ParamType pt = new ParamType();
								pt.setName(paramName);
								pt.setValue((String) y);
								trust.getParam().add(pt);
							}
						}
					}
				}
				
				tt.getTrust().add(trust);
			}
			
			idp.setTrusts(tt);
		}
	}
	
	
	
	private static long getLongValue(Object o, long defaultValue) {
		Long val = (Long) o;
		if (val == null) {
			return defaultValue;
		} else {
			return val;
		}
	}
	
	private static boolean getBoolValue(Object o, boolean defaultVal) {
		Boolean val = (Boolean) o;
		if (val == null) {
			return defaultVal;
		} else {
			return val;
		}
	}
	
	
	

	
	
	@Override
	public void loadDynamicApplications(ConfigManager cfgMgr, ProvisioningEngine provisioningEngine,
			Map<String, Attribute> init) throws ProvisioningException {
		this.tremolo = cfgMgr.getCfg();
		String k8sTarget = 	init.get("k8starget").getValues().get(0);
		String namespace = init.get("namespace").getValues().get(0);
		String uri = "/apis/openunison.tremolo.io/v1/namespaces/" + namespace + "/applications";
		
		
		this.provisioningEngine = provisioningEngine;
		this.cfgMgr = cfgMgr;
		
		this.k8sWatch = new K8sWatcher(k8sTarget,namespace,uri,this,cfgMgr,provisioningEngine);
		
		this.k8sWatch.initalRun();

	}



	@Override
	public void addObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
		String rawJson = item.toJSONString();
		StringBuffer b = new StringBuffer();
		b.setLength(0);
		OpenUnisonConfigLoader.integrateIncludes(b,rawJson);
		try {
			JSONObject newRoot = (JSONObject) new JSONParser().parse(b.toString());
			JSONObject metadata = (JSONObject) newRoot.get("metadata");
			
			if (metadata == null) {
				throw new ProvisioningException("No metadata");
			}
			
			String name = (String) metadata.get("name");
			
			logger.info("Adding application " + name);
			
			
			try {
				synchronized (GlobalEntries.getGlobalEntries().getConfigManager()) {
					ApplicationType app = this.createApplication(item, name);
					GlobalEntries.getGlobalEntries().getConfigManager().initializeUrls(
							GlobalEntries.getGlobalEntries().getConfigManager().addApplication(app)
					);
				}
				
			} catch (Exception e) {
				logger.warn("Could not initialize application " + name,e);
			}
			
		} catch (ParseException e) {
			throw new ProvisioningException("Could not parse application",e);
		}
		
	}



	@Override
	public void modifyObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
		String rawJson = item.toJSONString();
		StringBuffer b = new StringBuffer();
		b.setLength(0);
		OpenUnisonConfigLoader.integrateIncludes(b,rawJson);
		try {
			JSONObject newRoot = (JSONObject) new JSONParser().parse(b.toString());
			JSONObject metadata = (JSONObject) newRoot.get("metadata");
			
			if (metadata == null) {
				throw new ProvisioningException("No metadata");
			}
			
			String name = (String) metadata.get("name");
			
			logger.info("Modifying application " + name);
			
			try {
				synchronized (GlobalEntries.getGlobalEntries().getConfigManager()) {
					ApplicationType app = this.createApplication(item, name);
					GlobalEntries.getGlobalEntries().getConfigManager().deleteApp(app.getName());
					GlobalEntries.getGlobalEntries().getConfigManager().initializeUrls(
							GlobalEntries.getGlobalEntries().getConfigManager().addApplication(app)
					);
				}
				
			} catch (Exception e) {
				logger.warn("Could not modify application " + name,e);
			}
			
		} catch (ParseException e) {
			throw new ProvisioningException("Could not parse custom authorization",e);
		}
		
	}



	@Override
	public void deleteObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
		JSONObject metadata = (JSONObject) item.get("metadata");
		
		if (metadata == null) {
			throw new ProvisioningException("No metadata");
		}
		
		String name = (String) metadata.get("name");
		
		logger.info("Deleting application " + name);
		
		try {
			synchronized (GlobalEntries.getGlobalEntries().getConfigManager()) {
				GlobalEntries.getGlobalEntries().getConfigManager().deleteApp(name);
			}
			
		} catch (Exception e) {
			logger.warn("Could not delete application " + name,e);
		}
		
		
	}
	
	
}
