/*
Copyright 2015, 2018 Tremolo Security, Inc.

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

import java.io.IOException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;

import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.AuthMechType;
import com.tremolosecurity.config.xml.MechanismType;
import com.tremolosecurity.config.xml.ParamType;
import com.tremolosecurity.config.xml.ResultGroupType;
import com.tremolosecurity.config.xml.ResultType;

import com.tremolosecurity.proxy.ProxyRequest;
import com.tremolosecurity.proxy.ProxyResponse;
import com.tremolosecurity.proxy.ProxyUtil;
import com.tremolosecurity.proxy.TremoloHttpSession;
import com.tremolosecurity.proxy.auth.RequestHolder.HTTPMethod;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.results.CustomResult;
import com.tremolosecurity.proxy.util.NextSys;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.proxy.util.ProxyTools;
import com.tremolosecurity.saml.Attribute;

public class AuthMgrSys {
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(AuthMgrSys.class);
	
	
	public static final String AU_RES = "AUTOIDM_AU_RES";
	public static final String AZ_RES = "AUTOIDM_AZ_RES";
	
	public AuthMgrSys(ServletContext ctx) throws ServletException {
		
	}
	
	public void doAuthMgr(HttpServletRequest request,HttpServletResponse response, NextSys nextSys,AuthStep as) throws ServletException,IOException { 
		//String prefix = "/auth";
		//uri = uri.substring(prefix.length());
		
		String uri = request.getRequestURI();
		
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		ConfigManager cfgMgr = (ConfigManager) request.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);
		
		
		AuthController actl = (AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL);
		
		
		String actName = "";
		
		if (actl != null && actl.getHolder() == null && holder == null) {
			AuthMechanism authMech = cfgMgr.getAuthMech(request.getRequestURI());
			if (authMech != null) {
				String finalURL = authMech.getFinalURL(request, response);
				
				if (finalURL != null) {
				
					try {
						holder = cfgMgr.findURL(finalURL);
						String urlChain = holder.getUrl().getAuthChain();
						AuthChainType act = holder.getConfig().getAuthChains().get(urlChain);
						
						HashMap<String,Attribute> params = new HashMap<String,Attribute>();
						ProxyUtil.loadParams(request, params);
						
						actl.setHolder(new RequestHolder(HTTPMethod.GET,params,finalURL,true,act.getName(),((ProxyRequest) request).getQueryStringParams()));
						
						
						request.setAttribute(ProxyConstants.AUTOIDM_CFG, holder);
						
						String authChain = holder.getUrl().getAuthChain();
						
						holder.getConfig().getAuthManager().loadAmtParams(request.getSession(), act.getAuthMech().get(0));
					} catch (Exception e) {
						throw new ServletException("Could not run authentication",e);
					}
					
					
				}
			} else {
				throw new ServletException("Unknown URI : " + request.getRequestURI());
			}
		}
		
		if (actl != null && actl.getHolder() != null) {
			actName = actl.getHolder().getAuthChainName();
		} else {
			
			actName = holder.getUrl().getAuthChain();
			
		}
		
		
		AuthChainType act = cfgMgr.getAuthChains().get(actName);
		
		AuthMechanism mech = cfgMgr.getAuthMech(uri);
		if (mech == null) {
			nextSys.nextSys(request, response);
			return;
		}
		
		int step = 0;
		
		if (as != null) {
			AuthMechType amt = act.getAuthMech().get(as.getId());
			String amtName = amt.getName();
			MechanismType mech2 = cfgMgr.getAuthMechs().get(amtName);
			
			
			
			if (! request.getRequestURI().endsWith(mech2.getUri())) {
				logger.warn("Attempted double post");
				StringBuilder sb = new StringBuilder().append(cfgMgr.getAuthFormsPath()).append("/resetChain.jsp");
				response.sendRedirect(sb.toString());
				return;
			}
			
			step = as.getId();
		}
		
		
		
		
		String authMechName = act.getAuthMech().get(step).getName();
		MechanismType mt = cfgMgr.getAuthMechs().get(authMechName);
		
		String ruri = request.getRequestURI();
		String forwardedURI = (String) request.getAttribute("javax.servlet.forward.request_uri");
		
		/*Enumeration enumer = req.getAttributeNames();
		while (enumer.hasMoreElements()) {
			String name = (String) enumer.nextElement();
			System.out.println(name + "='" + req.getAttribute(name) + "'");
		}*/
		
		if (forwardedURI != null) {
			ruri = forwardedURI;
		}
		
		
		
		
	/*	if (! mt.getUri().equals(ruri)) {
			if (reqHolder.getCompletedMechs().get(lstep - 1)) {
				throw new ServletException("Error in chain");
			}
			
			
		}*/
		
		
		
		if (request.getMethod().equalsIgnoreCase("get")) {
			mech.doGet(request, response,as);
		} else if (request.getMethod().equalsIgnoreCase("post")) {
			mech.doPost(request, response,as);
		} else if (request.getMethod().equalsIgnoreCase("put")) {
			mech.doPut(request, response,as);
		} else if (request.getMethod().equalsIgnoreCase("delete")) {
			mech.doDelete(request, response,as);
		} else if (request.getMethod().equalsIgnoreCase("head")) {
			mech.doHead(request, response,as);
		} else if (request.getMethod().equalsIgnoreCase("options")) {
			mech.doOptions(request, response,as);
		} else {
			mech.doGet(request, response,as);
		}
		
		
		//check for a failed authenction
		//Boolean bool = (Boolean) request.getAttribute(AuthMgrSys.AU_RES);
		
		
		//HttpSession session = ((HttpServletRequest) request).getSession(true);
		
		//session = SharedSession.getSharedSession().getSession(session.getId());
		
		//AuthInfo authData = (AuthInfo) session.getAttribute(AuthSys.AUTH_DATA);
		
		//String urlChain = holder.getUrl().getAuthChain();
		//AuthChainType act = holder.getConfig().getAuthChains().get(urlChain);
		
		/*if (urlChain != null && bool != null) {
			processAuthResp(request, response, holder, bool);
		}*/
	}

	public void processAuthResp(HttpServletRequest request,
			HttpServletResponse response, UrlHolder holder, Boolean bool)
			throws IOException, InstantiationException, IllegalAccessException, ClassNotFoundException, ServletException {
		//authentication is required
		if (bool.booleanValue()) {
			//authentication succeeded
			String resGroup = getResponseSuccessGroup(holder);
			
			if (resGroup != null) {
				
				ResultGroupType resGrouping = holder.getConfig().getResultGroup(resGroup);
				proccessResponseResult(request, response, resGrouping,false,holder);
				
			}
		} else {
			//authentication failed
			String resGroup = getResponseFailGroup(holder);
			
			
			
			if (resGroup == null) {
				((HttpServletResponse) response).sendError(401);
				
			} else {
				
				ResultGroupType resGrouping = holder.getConfig().getResultGroup(resGroup);
				proccessResponseResult(request, response, resGrouping,true,holder);
				
			}
		}
	}
	
	private String getResponseFailGroup(UrlHolder holder) {
		String resGroup = null;
		
		if (holder.getUrl().getResults() != null) {
			resGroup = holder.getUrl().getResults().getAuFail();
		} 
		
		
		
		if (resGroup == null) {
			if (holder.getApp().getResults() != null) {
				resGroup = holder.getApp().getResults().getAuFail();
			}
		}
		return resGroup;
	}
	
	private String getResponseSuccessGroup(UrlHolder holder) {
		String resGroup = null;
		
		if (holder.getUrl().getResults() != null) {
			resGroup = holder.getUrl().getResults().getAuSuccess();
		} 
		
		
		
		if (resGroup == null) {
			if (holder.getApp().getResults() != null) {
				resGroup = holder.getApp().getResults().getAuSuccess();
			}
		}
		return resGroup;
	}

	private void proccessResponseResult(ServletRequest request,
			ServletResponse response,  ResultGroupType resGrouping,boolean forceError, UrlHolder holder)
			throws IOException, InstantiationException, IllegalAccessException, ClassNotFoundException, ServletException {
		String redir = null;
		
		if (resGrouping == null) {
			return;
		}
		
		Iterator<ResultType> it = resGrouping.getResult().iterator();
		while (it.hasNext()) {
			ResultType rt = it.next();
			if (rt.getType().equals("redirect")) {
				redir = rt.getValue();
			} else  if (rt.getType().equalsIgnoreCase("cookie")) {
				String val = rt.getValue();
				String name,value;
				
				boolean isCustom = rt.getSource().equalsIgnoreCase("custom");
				
				//failure cookie, so can not be based on the user
				if (rt.getSource().equalsIgnoreCase("static") || isCustom) {
					name = val.substring(0,val.indexOf('='));
					value = val.substring(val.indexOf('=') + 1);
				} else {
					name = "";
					value = "";
				}
				
				Cookie cookie = new Cookie(name,value);
				
				String domain = getCookieDomain(holder,(HttpServletRequest) request);
				if (domain != null) {
					cookie.setDomain(domain);
				}
				//cookie.setDomain(((HttpServletRequest) request).getServerName());
				cookie.setPath("/");
				
				if (isCustom) {
					CustomResult cr = (CustomResult) Class.forName(cookie.getValue()).newInstance();
					cr.createResultCookie(cookie, (HttpServletRequest)request, (HttpServletResponse)response);
				}
				
				((HttpServletResponse) response).addCookie(cookie);
				
			}
		}
		
		if (redir != null) {
			
			((ProxyResponse) response).removeHeader("Location");
			
			((HttpServletResponse) response).sendRedirect(redir);
		} else {
			if (forceError) {
				((HttpServletResponse) response).sendError(401);
			}
		}
	}

	private String getCookieDomain(UrlHolder holder, HttpServletRequest request) {
		return ProxyTools.getInstance().getCookieDomain(holder.getApp().getCookieConfig(), request);
	}
}
