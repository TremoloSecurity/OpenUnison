/*
Copyright 2015 Tremolo Security, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/


package com.tremolosecurity.proxy.auth;

import static org.apache.directory.ldap.client.api.search.FilterBuilder.equal;

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;
import org.joda.time.DateTime;
import org.stringtemplate.v4.ST;

import net.sourceforge.myvd.types.FilterNode;

import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.LDAPUrl;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.ApplicationType;
import com.tremolosecurity.config.xml.AzRuleType;
import com.tremolosecurity.config.xml.CookieConfigType;
import com.tremolosecurity.config.xml.ResultGroupType;
import com.tremolosecurity.config.xml.ResultType;
import com.tremolosecurity.log.AccessLog;
import com.tremolosecurity.log.AccessLog.AccessEvent;
import com.tremolosecurity.proxy.ProxyResponse;
import com.tremolosecurity.proxy.TremoloHttpSession;
import com.tremolosecurity.proxy.az.AzException;
import com.tremolosecurity.proxy.az.AzRule;
import com.tremolosecurity.proxy.az.CustomAuthorization;
import com.tremolosecurity.proxy.myvd.MyVDConnection;
import com.tremolosecurity.proxy.results.CustomResult;
import com.tremolosecurity.proxy.util.NextSys;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.proxy.util.ProxyTools;
import com.tremolosecurity.saml.Attribute;

public class AzSys {
	
	static Logger logger = Logger.getLogger(AzSys.class);

	public static final String AUTO_IDM_HTTP_HEADERS = "AUTO_IDM_HTTP_HEADERS";

	public static final String FORCE = "TREMOLO_FORCE";
	
	

	public void doAz(ServletRequest request, ServletResponse response,
			NextSys nextSys) throws IOException, ServletException,
			MalformedURLException {
		
		ConfigManager cfg = (ConfigManager) request.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);
		
		if (((HttpServletRequest) request).getRequestURI().startsWith(cfg.getAuthPath()) &&  (request.getAttribute(FORCE) == null || request.getAttribute(FORCE).equals("false"))) {
			nextSys.nextSys((HttpServletRequest) request, (HttpServletResponse) response);
			return;
		}
		
		HttpSession session = ((HttpServletRequest) request).getSession(true);
		
		
		
		
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		
		
		
		boolean doAz = holder.getUrl().getAzRules() != null && holder.getUrl().getAzRules().getRule().size() > 0;
		
		if (! doAz) {
			//chain.doFilter(request, response);
			nextSys.nextSys((HttpServletRequest) request,(HttpServletResponse) response);
			return;
		} 
		
		List<AzRuleType> rules = holder.getUrl().getAzRules().getRule();
		AuthInfo authData = ((AuthController) ((HttpServletRequest) request).getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
		boolean OK = checkRules(authData, holder.getConfig(), holder.getAzRules(),((HttpServletRequest) request).getSession(),holder.getApp(),null);
		
		if (OK) {
			
			
			
			
			
			
			String respGroup = getResponseSuccessGroup(holder);
			
			
			
			AccessLog.log(AccessEvent.AzSuccess, holder.getApp(), (HttpServletRequest) request, authData , respGroup != null ? respGroup : "NONE");
			
			if (respGroup != null) {
				try {
					processRequestResult(request, response, holder.getConfig().getResultGroup(respGroup),authData);
				} catch (InstantiationException | IllegalAccessException
						| ClassNotFoundException e) {
					throw new ServletException("Could not instantiate custom result group",e);
				}
			}
			
			
			
			//chain.doFilter(request, response);
			nextSys.nextSys((HttpServletRequest) request,(HttpServletResponse) response);
			
			if (respGroup != null) {
				try {
					proccessResponseResult(request, response, holder.getConfig().getResultGroup(respGroup), false,authData,holder.getApp().getCookieConfig());
				} catch (InstantiationException | IllegalAccessException
						| ClassNotFoundException e) {
					throw new ServletException("Could not instantiate custom result",e);
				}
			}
			
			
		} else {
			
			String respGroup = getResponseFailGroup(holder);
			AccessLog.log(AccessEvent.AzFail, holder.getApp(), (HttpServletRequest) request, authData , respGroup != null ? respGroup : "NONE");
			
			
			if (respGroup != null) {
				try {
					proccessResponseResult(request, response, holder.getConfig().getResultGroup(respGroup), true,authData, holder.getApp().getCookieConfig());
				} catch (InstantiationException | IllegalAccessException
						| ClassNotFoundException e) {
					throw new ServletException("Could not instantiate custom result",e);
				}
			} else {
				((HttpServletResponse) response).sendError(401);
			}
		}
	}
	

	public boolean checkRules(AuthInfo authData,ConfigManager cfgMgr,
			List<AzRule> rules,Map<String,Object> request) throws MalformedURLException {
		return checkRules(authData,cfgMgr,rules,null,null,request);
	}
	
	public boolean checkRules(AuthInfo authData,ConfigManager cfgMgr,
			List<AzRule> rules,HttpSession session,ApplicationType at,Map<String,Object> request) throws MalformedURLException {
		boolean OK=false;
		
		HashMap<UUID,DateTime> azCache = null;
		
		if (session != null) {
			azCache = (HashMap<UUID, DateTime>) session.getAttribute("TREMOLO_AZ_SESSION_CACHE");
			
			if (azCache == null) {
				azCache = new HashMap<UUID,DateTime>();
				session.setAttribute("TREMOLO_AZ_SESSION_CACHE", azCache);
			}
		}
		
		
		
		for (AzRule rule : rules) {
			
			if (azCache != null && azCache.get(rule.getGuid()) != null && azCache.get(rule.getGuid()).isAfterNow()) {
				OK = true;
			} else {
			
				OK = checkRule(authData, cfgMgr, at, OK, azCache, rule,request);
			
			}
			
			
			
			
		}
		
		return OK;
	}


	private boolean checkRule(AuthInfo authData, ConfigManager cfgMgr,
			ApplicationType at, boolean OK, HashMap<UUID, DateTime> azCache,
			AzRule rule,Map<String,Object> request) throws MalformedURLException {
		
		String localConstraint = rule.getConstraint();
		if (request != null) {
			ST st = new ST(localConstraint,'$','$');
			for (String key : request.keySet()) {
				st.add(key.replaceAll("[.]", "_"), request.get(key));
			}
			
			localConstraint = st.render();
		}
		
		switch (rule.getScope()) {
			case DN :
				if (authData.getUserDN().endsWith(localConstraint)) {
					OK = true;
					if (azCache != null) {
						azCache.put(rule.getGuid(), new DateTime().plus(at.getAzTimeoutMillis()));
					}
				}
				break;
				
			case Group :
				if (isUserInGroup(authData, cfgMgr, rule,localConstraint)) {
					OK = true;
					if (azCache != null) {
						azCache.put(rule.getGuid(), new DateTime().plus(at.getAzTimeoutMillis()));
					}
				}
				break;
			case DynamicGroup:
				if (isUserInGroup(authData, cfgMgr, rule,localConstraint)) {
					OK = true;
					if (azCache != null) {
						azCache.put(rule.getGuid(), new DateTime().plus(at.getAzTimeoutMillis()));
					}
				} else {
					ArrayList<String> attribs = new ArrayList<String>();
					attribs.add("memberURL");
					
					try {
						LDAPSearchResults rs = cfgMgr.getMyVD().search(localConstraint, 0, "(objectClass=*)", attribs);
						rs.hasMore();
						LDAPEntry entry = rs.next();
						String[] urls = entry.getAttribute("memberURL").getStringValueArray();
						for (int i=0;i<urls.length;i++) {
							String url = urls[i];
							LDAPUrl ldapUrl = new LDAPUrl(url);
							if (ldapUrl.getScope() == 0) {
								if (! authData.getUserDN().equalsIgnoreCase(ldapUrl.getDN())) {
									continue;
								}
							} else if (ldapUrl.getScope() == 1) {
								String oneLevelDN = authData.getUserDN().substring(authData.getUserDN().indexOf(',') + 1);
								if (! ldapUrl.getDN().equalsIgnoreCase(oneLevelDN)) {
									continue;
								}
								
							} else {
								if (! authData.getUserDN().endsWith(ldapUrl.getDN())) {
									continue;
								}
							}
							
							net.sourceforge.myvd.types.Filter filter = new net.sourceforge.myvd.types.Filter(ldapUrl.getFilter());
							if (this.checkEntry(filter.getRoot(), authData)) {
								OK = true;
								if (azCache != null) {
									azCache.put(rule.getGuid(), new DateTime().plus(at.getAzTimeoutMillis()));
								}
							}
						}
					} catch (LDAPException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					
					}
				}
				break;
			case Filter:
				try {
					net.sourceforge.myvd.types.Filter filter = new net.sourceforge.myvd.types.Filter(localConstraint);
					if (this.checkEntry(filter.getRoot(), authData)) {
						OK = true;
						if (azCache != null) {
							azCache.put(rule.getGuid(), new DateTime().plus(at.getAzTimeoutMillis()));
						}
					}
					
					
				} catch (LDAPException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				break;
				
			case Custom :
				
				
				
				CustomAuthorization customAz = rule.getCustomAuthorization();
				if (customAz == null) {
					cfgMgr.getCustomAuthorizations().get(localConstraint);
				}
				
				
				if (customAz == null) {
					logger.warn("Rule '" + localConstraint + "' does not exist, failing");
					OK = false;
				} else {
					try {
						if (customAz.isAuthorized(authData)) {
							OK = true;
							if (azCache != null) {
								azCache.put(rule.getGuid(), new DateTime().plus(at.getAzTimeoutMillis()));
							}
						}
					} catch (AzException e) {
						logger.warn("Could not run authorization",e);
					}
				}
				break;
					
		}
		return OK;
	}

	private boolean isUserInGroup(AuthInfo authData, ConfigManager cfgMgr,
			AzRule rule,String localConstraint) {
		boolean OK = false;
		MyVDConnection con = cfgMgr.getMyVD();
		ArrayList<String> attribs = new ArrayList<String>();
		attribs.add("1.1");
		try {
			
			
			
			
			
			
			LDAPSearchResults res = con.search(localConstraint, 0, equal("uniqueMember",authData.getUserDN()).toString(), attribs);
			
			if (res.hasMore()) {
				OK = true;
				res.next();
			}
			
			
		} catch (LDAPException e) {
			logger.error("Could not parse",e);
		}
		
		return OK;
	}


	
	public boolean checkEntry(FilterNode filter,AuthInfo authInfo) {
		Iterator<FilterNode> it;
		//LDAPAttributeSet attribs;
		Attribute attrib;
		Iterator<String> itAttr;
		
		
		
		switch (filter.getType()) {
			case PRESENCE : return authInfo.getAttribs().get(filter.getName()) != null;
			case SUBSTR: 
					   //attribs = entry.getAttributeSet();
					   attrib = authInfo.getAttribs().get(filter.getName());
					   
					   if (attrib == null) {
						   return false;
					   }
					   
					   itAttr = attrib.getValues().iterator();
					   String compval = filter.getValue().replaceAll("\\*", ".*");
					   while (itAttr.hasNext()) {
						   if (itAttr.next().matches(compval)) {
							   return true;
						   }
					   }
					   
					   return false;
				   
			case EQUALS :  attrib = authInfo.getAttribs().get(filter.getName());
						   
						   if (attrib == null) {
							   return false;
						   }
						   
						   for (String val : attrib.getValues()) {
							   if (val.equalsIgnoreCase(filter.getValue())) {
								   return true;
							   }
						   }
						   
						   
						   
						   return false;
			case GREATER_THEN : attrib = authInfo.getAttribs().get(filter.getName());
								   
								   if (attrib == null) {
									   return false;
								   }
								   
								   itAttr = attrib.getValues().iterator();
								   while (itAttr.hasNext()) {
									   if (itAttr.next().compareToIgnoreCase(filter.getValue()) > 0) {
										   return true;
									   }
								   }
								   
								   return false;
			case LESS_THEN : attrib = authInfo.getAttribs().get(filter.getName());
							   
							   if (attrib == null) {
								   return false;
							   }
							   
							   itAttr = attrib.getValues().iterator();
							   while (itAttr.hasNext()) {
								   if (itAttr.next().compareToIgnoreCase(filter.getValue()) < 0) {
									   return true;
								   }
							   }
							   
							   return false;
			case AND : 
					   it = filter.getChildren().iterator();
					   while (it.hasNext()) {
						   if (!  checkEntry(it.next(),authInfo)) {
							   return false;
						   }
					   }
					   return true;
					   
			case OR :  it = filter.getChildren().iterator();
					   while (it.hasNext()) {
						   if (checkEntry(it.next(),authInfo)) {
							   return true;
						   }
					   }
					   return false;
					   
			
			case NOT : return ! checkEntry(filter.getNot(),authInfo);
					   
		}
		
		return false;
	}
	
	public String getResponseFailGroup(UrlHolder holder) {
		String resGroup = null;
		
		if (holder.getUrl().getResults() != null) {
			resGroup = holder.getUrl().getResults().getAzFail();
		} 
		
		
		
		if (resGroup == null) {
			if (holder.getApp().getResults() != null) {
				resGroup = holder.getApp().getResults().getAzFail();
			}
		}
		return resGroup;
	}
	
	public String getResponseSuccessGroup(UrlHolder holder) {
		String resGroup = null;
		
		if (holder.getUrl().getResults() != null) {
			resGroup = holder.getUrl().getResults().getAzSuccess();
		} 
		
		
		
		if (resGroup == null) {
			if (holder.getApp().getResults() != null) {
				resGroup = holder.getApp().getResults().getAzSuccess();
			}
		}
		return resGroup;
	}

	public void processRequestResult(ServletRequest request,ServletResponse response,ResultGroupType resGrouping, AuthInfo authData) throws ServletException, InstantiationException, IllegalAccessException, ClassNotFoundException {
		String redir = null;
		
		if (resGrouping == null) {
			return;
		}
		
		Iterator<ResultType> it = resGrouping.getResult().iterator();
		while (it.hasNext()) {
			ResultType rt = it.next();
			if (rt.getType().equals("header")) {
				String val = rt.getValue();
				String name,value;

				name = val.substring(0,val.indexOf('='));
				value = val.substring(val.indexOf('=') + 1);

				HashMap<String,Attribute> headers = (HashMap<String,Attribute>) request.getAttribute(AzSys.AUTO_IDM_HTTP_HEADERS);
				if (headers == null) {
					headers = new HashMap<String,Attribute>();
					request.setAttribute(AzSys.AUTO_IDM_HTTP_HEADERS, headers);
				}
				
				Attribute attrib = headers.get(name);
				if (attrib == null) {
					attrib = new Attribute(name);
					headers.put(attrib.getName(), attrib);
				}
				
				
				
				if (rt.getSource().equalsIgnoreCase("static")) {
					attrib.getValues().add(value);
					
					
				} else if (rt.getSource().equalsIgnoreCase("user")) {
					if (authData.getAttribs().get(value) != null) {
						attrib.getValues().addAll(authData.getAttribs().get(value).getValues());
					}
					
				} else if (rt.getSource().equalsIgnoreCase("custom")) {
					CustomResult cr = (CustomResult) Class.forName(value).newInstance();
					attrib.getValues().add(cr.getResultValue((HttpServletRequest)request, (HttpServletResponse)response));
				} else {
					attrib.getValues().add("");
				}
			} 
		}
	}
	
	public void proccessResponseResult(ServletRequest request,
			ServletResponse response,  ResultGroupType resGrouping,boolean forceError,AuthInfo authData, CookieConfigType cookieCfg)
			throws IOException, InstantiationException, IllegalAccessException, ClassNotFoundException, ServletException {
		String redir = null;
		
		if (resGrouping == null) {
			return;
		}
		
		Iterator<ResultType> it = resGrouping.getResult().iterator();
		while (it.hasNext()) {
			ResultType rt = it.next();
			if (rt.getType().equals("redirect")) {
				boolean isCustom = rt.getSource().equalsIgnoreCase("custom");
				if (! isCustom) {
					redir = rt.getValue();
				} else {
					if (isCustom) {
						CustomResult cr = (CustomResult) Class.forName(rt.getValue()).newInstance();
						redir = cr.getResultValue((HttpServletRequest)request, (HttpServletResponse)response);
					}
				}
			} else  if (rt.getType().equalsIgnoreCase("cookie")) {
				String val = rt.getValue();
				String name,value;
				
				boolean isCustom = rt.getSource().equalsIgnoreCase("custom");
				
				//failure cookie, so can not be based on the user
				if (rt.getSource().equalsIgnoreCase("static")) {
					name = val.substring(0,val.indexOf('='));
					value = val.substring(val.indexOf('=') + 1);
				} else if (rt.getSource().equalsIgnoreCase("user")  || isCustom) {
					
					name = val.substring(0,val.indexOf('='));
					value = val.substring(val.indexOf('=') + 1);
					if (authData.getAttribs().get(value) != null) {
						value = authData.getAttribs().get(value).getValues().get(0);
					}
					//attrib.getValues().addAll(authData.getAttribs().get(value).getValues());
				} else {
					name = "";
					value = "";
				}
				
				Cookie cookie = new Cookie(name,value);
				//cookie.setDomain(((HttpServletRequest) request).getServerName() );
				String domain = ProxyTools.getInstance().getCookieDomain(cookieCfg, (HttpServletRequest) request);
				if (domain != null) {
					cookie.setDomain(domain);
				}
				cookie.setPath("/");
				cookie.setSecure(false);
				
				
				if (isCustom) {
					CustomResult cr = (CustomResult) Class.forName(cookie.getValue()).newInstance();
					cr.createResultCookie(cookie, (HttpServletRequest)request, (HttpServletResponse)response);
				}
				
				
				((HttpServletResponse) response).addCookie(cookie);
				
			}
		}
		
		if (redir != null) {

			((HttpServletResponse) response).sendRedirect(redir);
		} else {
			if (forceError) {
				((HttpServletResponse) response).sendError(401);
			}
		}
	}
}
