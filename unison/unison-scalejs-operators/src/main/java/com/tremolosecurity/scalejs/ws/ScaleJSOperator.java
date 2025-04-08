//    Copyright 2018 Tremolo Security, Inc.
// 
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
// 
//        http://www.apache.org/licenses/LICENSE-2.0
// 
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

package com.tremolosecurity.scalejs.ws;

import static org.apache.directory.ldap.client.api.search.FilterBuilder.*;

import java.io.IOException;
import java.lang.reflect.Type;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResult;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.ApplicationType;
import com.tremolosecurity.config.xml.FilterConfigType;
import com.tremolosecurity.config.xml.ParamType;
import com.tremolosecurity.config.xml.ParamWithValueType;
import com.tremolosecurity.config.xml.UrlType;
import com.tremolosecurity.provisioning.service.util.TremoloUser;
import com.tremolosecurity.provisioning.service.util.WFCall;
import com.tremolosecurity.proxy.ProxyResponse;
import com.tremolosecurity.proxy.ProxySys;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.scalejs.cfg.ScaleConfig;
import com.tremolosecurity.scalejs.data.ScaleError;
import com.tremolosecurity.scalejs.sdk.UiDecisions;
import com.tremolosecurity.scalejs.util.ScaleJSUtils;
import com.tremolosecurity.scalejs.ws.ScaleMain;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.scalejs.operators.config.AttributeConfig;
import com.tremolosecurity.scalejs.operators.config.OperatorsConfig;
import com.tremolosecurity.scalejs.operators.data.OpsSearch;
import com.tremolosecurity.scalejs.operators.data.OpsUpdate;
import com.tremolosecurity.scalejs.operators.data.OpsUserData;
import com.tremolosecurity.proxy.auth.AuthController;

import org.apache.directory.ldap.client.api.search.FilterBuilder;
import org.apache.logging.log4j.Logger;

import net.sourceforge.myvd.types.Filter;
import net.sourceforge.myvd.util.EntryUtil;

/**
 * ScaleJSOperator
 * 
 * 
 */
public class ScaleJSOperator implements HttpFilter {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(ScaleJSOperator.class.getName());
	private OperatorsConfig config;
	private UrlType scaleJsUrl;
	private UiDecisions dec;
	private String scalejsAppName;
	private String scaleMainURL;
	private ScaleConfig scaleMainConfig;
	

	@Override
	public void doFilter(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {




		Gson gson = new Gson();
		request.getServletRequest().setAttribute("com.tremolosecurity.unison.proxy.noRedirectOnError", "com.tremolosecurity.unison.proxy.noRedirectOnError");
		try {
			if (request.getRequestURI().endsWith("/ops/config")) {
				ScaleJSUtils.addCacheHeaders(response);
				response.setContentType("application/json; charset=UTF-8");
				((ProxyResponse) response.getServletResponse()).pushHeadersAndCookies(null);
				response.getWriter().println(gson.toJson(this.config).trim());
			} else if (request.getRequestURI().endsWith("/ops/search")) {
				runSearch(request, response, gson);

			} else if (request.getRequestURI().endsWith("/ops/user") && request.getMethod().equalsIgnoreCase("GET")) {
				lookupUser(request, response, gson);
			} else if (request.getRequestURI().endsWith("/ops/user") && request.getMethod().equalsIgnoreCase("POST")) {
				AuthInfo loggedIn = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
				
				String json = new String((byte[]) request.getAttribute(ProxySys.MSG_BODY));
				OpsUpdate updateInput = gson.fromJson(json,OpsUpdate.class);

				if (this.scaleMainConfig == null) {
					UrlHolder holder = GlobalEntries.getGlobalEntries().getConfigManager().findURL(this.scaleMainURL);
					for (HttpFilter filter : holder.getFilterChain()) {
						if (filter instanceof ScaleMain) {
							ScaleMain scaleMain = (ScaleMain) filter;
							this.scaleMainConfig = scaleMain.scaleConfig;
						}
					}
				}
		
				String dn = updateInput.getDn();
				LDAPSearchResults res = GlobalEntries.getGlobalEntries().getConfigManager().getMyVD().search(dn, 0, "(objectClass=*)", new ArrayList<String>());
				if (! res.hasMore()) {
					throw new Exception("Could not locate user '" + dn + "'");
				}
				LDAPEntry entry = res.next();
				while (res.hasMore()) res.next();
				
				AuthInfo userData = new AuthInfo();
				userData.setUserDN(entry.getDN(),null);
				LDAPAttributeSet attrs = entry.getAttributeSet();
				for (Object obj : attrs) {
					LDAPAttribute attr = (LDAPAttribute) obj;
					
				
					
					Attribute attrib = new Attribute(attr.getName());
					String[] vals = attr.getStringValueArray();
					for (String val : vals) {
						attrib.getValues().add(val);
					}
					
					userData.getAttribs().put(attrib.getName(), attrib);
				}

				ScaleError errors = new ScaleError();

				Set<String> allowedAttrs = null;

				if (this.scaleMainConfig.getUiDecisions() != null) {
					allowedAttrs = this.scaleMainConfig.getUiDecisions().availableAttributes(userData, request.getServletRequest());
				}

				HashMap<String,String> values = new HashMap<String,String>();
				boolean ok = true;

				for (Attribute attr : updateInput.getAttributes()) {
					String attributeName = attr.getName();
			
					if (allowedAttrs == null || allowedAttrs.contains(attributeName)) {
					
						String value = attr.getValues().get(0);
						
						
						
						if (this.scaleMainConfig.getAttributes().get(attributeName) == null) {
							errors.getErrors().add("Invalid attribute : '" + attributeName + "'");
							ok = false;
						} else if (this.scaleMainConfig.getAttributes().get(attributeName).isReadOnly()) {
							errors.getErrors().add("Attribute is read only : '" + this.scaleMainConfig.getAttributes().get(attributeName).getDisplayName() + "'");
							ok = false;
						} else if (this.scaleMainConfig.getAttributes().get(attributeName).isRequired() && value.length() == 0) {
							errors.getErrors().add("Attribute is required : '" + this.scaleMainConfig.getAttributes().get(attributeName).getDisplayName() + "'");
							ok = false;
						} else if (this.scaleMainConfig.getAttributes().get(attributeName).getMinChars() > 0 && this.scaleMainConfig.getAttributes().get(attributeName).getMinChars() > value.length()) {
							errors.getErrors().add(this.scaleMainConfig.getAttributes().get(attributeName).getDisplayName() + " must have at least " + this.scaleMainConfig.getAttributes().get(attributeName).getMinChars() + " characters");
							ok = false;
						} else if (this.scaleMainConfig.getAttributes().get(attributeName).getMaxChars() > 0 && this.scaleMainConfig.getAttributes().get(attributeName).getMaxChars() < value.length()) {
							errors.getErrors().add(this.scaleMainConfig.getAttributes().get(attributeName).getDisplayName() + " must have at most " + this.scaleMainConfig.getAttributes().get(attributeName).getMaxChars() + " characters");
							ok = false;
						} else if (this.scaleMainConfig.getAttributes().get(attributeName).getPattern() != null) {
							try {
								Matcher m = this.scaleMainConfig.getAttributes().get(attributeName).getPattern().matcher(value);
								if (m == null || ! m.matches()) {
									ok = false;
								}
							} catch (Exception e) {
								ok = false;
							}
							
							if (!ok) {
								errors.getErrors().add("Attribute value not valid : '" + this.scaleMainConfig.getAttributes().get(attributeName).getDisplayName() + "' - " + this.scaleMainConfig.getAttributes().get(attributeName).getRegExFailedMsg());
							}
						}
						
						values.put(attributeName, value);
					}

				}

				for (String attrName : this.scaleMainConfig.getAttributes().keySet()) {
					if (this.scaleMainConfig.getAttributes().get(attrName).isRequired() && ! values.containsKey(attrName) && (allowedAttrs == null || allowedAttrs.contains(attrName) )) {
						errors.getErrors().add("Attribute is required : '" + this.scaleMainConfig.getAttributes().get(attrName).getDisplayName() + "'");
						ok = false;
					}
				}

				if (updateInput.getReason() == null || updateInput.getReason().trim().isEmpty()) {
					errors.getErrors().add("Reason For Updates Required");
					ok = false;
				}
				
				if (ok) {
					
					ConfigManager cfgMgr = GlobalEntries.getGlobalEntries().getConfigManager();
					WFCall wfCall = new WFCall();
					wfCall.setName(this.scaleMainConfig.getWorkflowName());
					wfCall.setReason(updateInput.getReason());
					wfCall.setUidAttributeName(this.scaleMainConfig.getUidAttributeName());
					wfCall.setRequestor(loggedIn.getAttribs().get(this.scaleMainConfig.getUidAttributeName()).getValues().get(0));
					
					TremoloUser tu = new TremoloUser();
					tu.setUid(userData.getAttribs().get(this.scaleMainConfig.getUidAttributeName()).getValues().get(0));
					for (String name : values.keySet()) {
						tu.getAttributes().add(new Attribute(name,values.get(name)));
					}
					
					tu.getAttributes().add(new Attribute(this.scaleMainConfig.getUidAttributeName(),userData.getAttribs().get(this.scaleMainConfig.getUidAttributeName()).getValues().get(0)));
					
					wfCall.setUser(tu);
					
					try {
						com.tremolosecurity.provisioning.workflow.ExecuteWorkflow exec = new com.tremolosecurity.provisioning.workflow.ExecuteWorkflow();
						exec.execute(wfCall, GlobalEntries.getGlobalEntries().getConfigManager());
						
					} catch (Exception e) {
						logger.error("Could not update user",e);
						response.setStatus(500);
						ScaleError error = new ScaleError();
						error.getErrors().add("Please contact your system administrator");
						ScaleJSUtils.addCacheHeaders(response);
						((ProxyResponse) response.getServletResponse()).pushHeadersAndCookies(null);
						response.getWriter().print(gson.toJson(error).trim());
						response.getWriter().flush();
					}
					
					
				} else {
					response.setStatus(500);
					ScaleJSUtils.addCacheHeaders(response);
					((ProxyResponse) response.getServletResponse()).pushHeadersAndCookies(null);
					response.getWriter().print(gson.toJson(errors).trim());
					response.getWriter().flush();
				}
			}
		} catch (Throwable t) {
			logger.error("Could not execute request",t);
			
			response.setStatus(500);
			ScaleError error = new ScaleError();
			error.getErrors().add("Operation not supported");
			ScaleJSUtils.addCacheHeaders(response);
			((ProxyResponse) response.getServletResponse()).pushHeadersAndCookies(null);
			response.getWriter().print(gson.toJson(error).trim());
			response.getWriter().flush();
			
		}



	}

	private void lookupUser(HttpFilterRequest request, HttpFilterResponse response, Gson gson)
			throws Exception, LDAPException, IOException {
		if (this.scaleMainConfig == null) {
			UrlHolder holder = GlobalEntries.getGlobalEntries().getConfigManager().findURL(this.scaleMainURL);
			for (HttpFilter filter : holder.getFilterChain()) {
				if (filter instanceof ScaleMain) {
					ScaleMain scaleMain = (ScaleMain) filter;
					this.scaleMainConfig = scaleMain.scaleConfig;
				}
			}
		}

		String dn = request.getParameter("dn").getValues().get(0);
		
		FilterBuilder baseFilter = (FilterBuilder) request.getAttribute("ops.search.filter");
		String filter = "(objectClass=*)";
		if (baseFilter != null) {
			filter = baseFilter.toString();
		}
		LDAPSearchResults res = GlobalEntries.getGlobalEntries().getConfigManager().getMyVD().search(dn, 0, filter, new ArrayList<String>());
		if (! res.hasMore()) {
			throw new Exception("Could not locate user '" + dn + "'");
		}
		LDAPEntry entry = res.next();
		while (res.hasMore()) res.next();
		
		AuthInfo userData = new AuthInfo();
		userData.setUserDN(entry.getDN(),null);
		LDAPAttributeSet attrs = entry.getAttributeSet();
		for (Object obj : attrs) {
			LDAPAttribute attr = (LDAPAttribute) obj;
			
		
			
			Attribute attrib = new Attribute(attr.getName());
			String[] vals = attr.getStringValueArray();
			for (String val : vals) {
				attrib.getValues().add(val);
			}
			
			userData.getAttribs().put(attrib.getName(), attrib);
		}


		Set<String> allowedAttrs = null;

		if (scaleMainConfig.getUiDecisions() != null) {
			allowedAttrs = this.scaleMainConfig.getUiDecisions().availableAttributes(userData, request.getServletRequest());
		}

		OpsUserData userToSend = new OpsUserData();
		userToSend.setDn(userData.getUserDN());
		
		
		
		for (String attrName : this.scaleMainConfig.getUserAttributeList()) {
			
			if (allowedAttrs == null || allowedAttrs.contains(attrName)) {
				Attribute attr = new Attribute(attrName);
				Attribute fromUser = userData.getAttribs().get(attrName);
				if (fromUser != null) {
					attr.getValues().addAll(fromUser.getValues());
					
					if (attrName.equalsIgnoreCase(this.scaleMainConfig.getUidAttributeName())) {
						userToSend.setUid(fromUser.getValues().get(0));
					}
				}
				userToSend.getAttributes().add(attr);
			}
		}
		
		
		if (this.scaleMainConfig.getRoleAttribute() != null && ! this.scaleMainConfig.getRoleAttribute().isEmpty()) {
			Attribute fromUser = userData.getAttribs().get(this.scaleMainConfig.getRoleAttribute());
			Attribute attr = new Attribute(this.scaleMainConfig.getRoleAttribute());
			if (fromUser != null) {
				attr.getValues().addAll(fromUser.getValues());
				userToSend.getGroups().clear();
				userToSend.getGroups().addAll(fromUser.getValues());
			}
			
			userToSend.getAttributes().add(attr);
			
		} else {
		
		
			ArrayList<String> attrNames = new ArrayList<String>();
			attrNames.add("cn");
			attrNames.add(GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getGroupMemberAttribute());
			res = GlobalEntries.getGlobalEntries().getConfigManager().getMyVD().search(GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getLdapRoot(), 2, equal(GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getGroupMemberAttribute(),dn).toString(), attrNames);
			
			net.sourceforge.myvd.types.Filter ldapFiltertoCheck = new net.sourceforge.myvd.types.Filter(equal(GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getGroupMemberAttribute(),dn).toString());
	
			
			while (res.hasMore()) {
				entry = res.next();
				if (ldapFiltertoCheck.getRoot().checkEntry(entry)) {
					LDAPAttribute la = entry.getAttribute("cn");
					if (la != null) {
						String val = la.getStringValue();
						if (! userToSend.getGroups().contains(val)) {
							userToSend.getGroups().add(val);
						}
					}
				}
			}
		}


		if (scaleMainConfig.getUiDecisions() != null) {
			Set<String> smAllowedAttrs = this.scaleMainConfig.getUiDecisions().availableAttributes(userData, request.getServletRequest());
			ScaleConfig local = new ScaleConfig(this.scaleMainConfig);
			if (smAllowedAttrs != null) {
				
				for (String attrName : this.scaleMainConfig.getAttributes().keySet()) {
					if (! smAllowedAttrs.contains(attrName)) {
						local.getAttributes().remove(attrName);
					}
				}
			}

			userToSend.setMetaData(local.getAttributes());
			
			userToSend.setCanEditUser(this.scaleMainConfig.getUiDecisions().canEditUser(userData, request.getServletRequest()));
		} else {
			userToSend.setMetaData(scaleMainConfig.getAttributes());
			userToSend.setCanEditUser(scaleMainConfig.isCanEditUser());
		}
		ScaleJSUtils.addCacheHeaders(response);
		response.setContentType("application/json; charset=UTF-8");
		((ProxyResponse) response.getServletResponse()).pushHeadersAndCookies(null);
		response.getWriter().println(gson.toJson(userToSend).trim());
	}

	private void runSearch(HttpFilterRequest request, HttpFilterResponse response, Gson gson)
			throws Exception, LDAPException, IOException {
		String json = new String((byte[]) request.getAttribute(ProxySys.MSG_BODY));
		OpsSearch opsSearch = gson.fromJson(json, OpsSearch.class);
		List<AttributeConfig> forSearch = opsSearch.getToSearch();

		List<FilterBuilder> filter = new ArrayList<FilterBuilder>();

		for (AttributeConfig attr : forSearch) {
			if (attr.isPicked()) {
				filter.add(equal(attr.getName(), attr.getValue()));
			}
		}

		FilterBuilder[] fb = new FilterBuilder[filter.size()];
		filter.toArray(fb);
		
		
		FilterBuilder baseFilter = (FilterBuilder) request.getAttribute("ops.search.filter");
		
		String filterString;
		
		if (baseFilter != null) {
			FilterBuilder localFilter = and(fb);
			filterString = and(localFilter,baseFilter).toString();
		} else {
			filterString = and(fb).toString(); 
		}
		
		
		String searchBase = this.config.getBaseLabelToDN().get(opsSearch.getBase());
		if (searchBase == null) {
			throw new Exception("Invalid search base");
		}

		List<HashMap<String, String>> resList = new ArrayList<HashMap<String, String>>();

		LDAPSearchResults res = GlobalEntries.getGlobalEntries().getConfigManager().getMyVD().search(searchBase, 2,
				filterString, new ArrayList<String>());
		while (res.hasMore()) {
			HashMap<String, String> ret = new HashMap<String, String>();
			resList.add(ret);

			LDAPEntry entry = res.next();
			ret.put("dn", entry.getDN());
			for (AttributeConfig attr : this.config.getResultsAttributes()) {
				
				if (entry.getAttribute(attr.getName()) != null) {
					String val = entry.getAttribute(attr.getName()).getStringValue();
					ret.put(attr.getName(), val);
				} else {
					ret.put(attr.getName(), "");
				}
			}
		}

		ScaleJSUtils.addCacheHeaders(response);
		response.setContentType("application/json; charset=UTF-8");
		((ProxyResponse) response.getServletResponse()).pushHeadersAndCookies(null);
		response.getWriter().println(gson.toJson(resList).trim());
	}

	@Override
	public void filterResponseText(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain,
			StringBuffer data) throws Exception {

	}

	@Override
	public void filterResponseBinary(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain,
			byte[] data, int length) throws Exception {

	}

	@Override
	public void initFilter(HttpFilterConfig config) throws Exception {
		this.config = new OperatorsConfig();

		Attribute bases = config.getAttribute("bases");
		if (bases == null) {
			throw new Exception("bases not set");
		}

		for (String base : bases.getValues()) {
			String desc = base.substring(0, base.indexOf('='));
			String ldap = base.substring(base.indexOf('=') + 1);
			this.config.getBaseLabelToDN().put(desc, ldap);
			this.config.getSearchBases().add(desc);
		}

		Attribute attr = config.getAttribute("searchableAttributes");
		if (attr == null) {
			throw new Exception("searchableAttributes not found");
		}

		for (String searchable : attr.getValues()) {
			String name = searchable.substring(0, searchable.indexOf('='));
			String label = searchable.substring(searchable.indexOf('=') + 1);
			this.config.getSearchableAttributes().add(new AttributeConfig(name, label, ""));
		}

		attr = config.getAttribute("resultAttributes");
		if (attr == null) {
			throw new Exception("resultAttributes not found");
		}

		for (String resultAttr : attr.getValues()) {
			String name = resultAttr.substring(0, resultAttr.indexOf('='));
			String label = resultAttr.substring(resultAttr.indexOf('=') + 1);
			this.config.getResultsAttributes().add(new AttributeConfig(name, label, ""));
		}

		this.config.setScaleJsMainUri(this.loadAttributeValue("scaleMainURI", "Scale Main URI", config));
		this.config.setHomeUrl(this.loadAttributeValue("homeUrl", "Home URL", config));

		this.scalejsAppName = this.loadAttributeValue("scaleMainAppName", "Scale Main Application", config);

		ApplicationType app = null;
		for (ApplicationType at : config.getConfigManager().getCfg().getApplications().getApplication()) {
			if (at.getName().equalsIgnoreCase(scalejsAppName)) {
				app = at;
			}
		}

		if (app == null) {
			throw new Exception(scalejsAppName + " does not exist");
		}

		for (UrlType url : app.getUrls().getUrl()) {
			if (url.getUri().equalsIgnoreCase(this.config.getScaleJsMainUri())) {
				this.scaleJsUrl = url;
			}
		}

		if (this.scaleJsUrl == null) {
			throw new Exception("Could not find url for ScaleJS Main");
		}

		this.scaleMainURL = "https://" + this.scaleJsUrl.getHost().get(0) + this.scaleJsUrl.getUri();

		HashMap<String,Attribute> decCfg = new HashMap<String,Attribute>();
		
		for (FilterConfigType filter : this.scaleJsUrl.getFilterChain().getFilter()) {
			if (filter.getClazz().equalsIgnoreCase("com.tremolosecurity.scalejs.ws.ScaleMain")) {
				for (ParamWithValueType pt : filter.getParam()) {
					if (pt.getName().equalsIgnoreCase("uiHelperClassName")) {
						this.dec = (UiDecisions) Class.forName(pt.getValue()).newInstance();
					} else if (pt.getName().equalsIgnoreCase("uihelper.params")) {
						String v = pt.getValue();
						String name = v.substring(0,v.indexOf('='));
						String value = v.substring(v.indexOf('=') + 1);
						Attribute param = decCfg.get(name);
						if (param == null) {
							param = new Attribute(name);
							decCfg.put(name, param);
						}
						param.getValues().add(value);
					}
				}
			}
		}

		if (this.dec != null) {
			this.dec.init(decCfg);
		}

		String tmp = this.loadOptionalAttributeValue("approveChecked", "approveChecked", config);
		if (tmp != null) {
			this.config.setApproveChecked(tmp.equalsIgnoreCase("true"));
		} else {
			this.config.setApproveChecked(false);
		}
		
		tmp = this.loadOptionalAttributeValue("showPreApprove", "showPreApprove", config);
		if (tmp != null) {
			this.config.setShowPreApprove(tmp.equalsIgnoreCase("true"));
		} else {
			this.config.setShowPreApprove(true);
		}
		
		
		tmp = this.loadOptionalAttributeValue("approvedLabel", "approvedLabel", config);
		if (tmp != null) {
			this.config.setApprovedLabel(tmp);
		}
		
		tmp = this.loadOptionalAttributeValue("deniedLabel", "deniedLabel", config);
		if (tmp != null) {
			this.config.setDeniedLabel(tmp);
		}
		
		tmp = this.loadOptionalAttributeValue("reasonApprovedLabel", "reasonApprovedLabel", config);
		if (tmp != null) {
			this.config.setReasonApprovedLabel(tmp);
		}
		
		tmp = this.loadOptionalAttributeValue("reasonDeniedLabel", "reasonDeniedLabel", config);
		if (tmp != null) {
			this.config.setReasonDeniedLabel(tmp);
		}
		
		tmp = this.loadOptionalAttributeValue("maxWidth", "maxWidth", config);
		if (tmp != null) {
			this.config.setMaxWidth(tmp);
		}
		
		tmp = this.loadOptionalAttributeValue("attributesWidth", "attributesWidth", config);
		if (tmp != null) {
			this.config.setAttributesWidth(Integer.parseInt(tmp));
		}
		
		tmp = this.loadOptionalAttributeValue("rolesWidth", "rolesWidth", config);
		if (tmp != null) {
			this.config.setRolesWidth(Integer.parseInt(tmp));
		}

	}

	

    private String loadAttributeValue(String name,String label,HttpFilterConfig config) throws Exception {
		Attribute attr = config.getAttribute(name);
		if (attr == null) {
			throw new Exception(label + " not found");
		}
		
		String val = attr.getValues().get(0);
		logger.info(label + ": '" + val + "'");
		
		return val;
	}
	
	private String loadOptionalAttributeValue(String name,String label,HttpFilterConfig config) throws Exception {
		Attribute attr = config.getAttribute(name);
		if (attr == null) {
			logger.warn(label + " not found");
			return null;
		}
		
		String val = attr.getValues().get(0);
		logger.info(label + ": '" + val + "'");
		
		return val;
	}
}