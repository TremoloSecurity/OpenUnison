/*
Copyright 2015, 2016 Tremolo Security, Inc.

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


package com.tremolosecurity.proxy.filters;

import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.ApplicationType;
import com.tremolosecurity.config.xml.AzRuleType;
import com.tremolosecurity.log.AccessLog;
import com.tremolosecurity.log.AccessLog.AccessEvent;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.auth.AzSys;
import com.tremolosecurity.proxy.az.AzRule;
import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;



public class AzFilter implements HttpFilter {

	AzSys az;
	
	List<AzRule> localRules;
	
	String azSuccess;
	String azFail;
	
	@Override
	public void doFilter(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		
		HttpSession session = request.getSession();
		AuthInfo authData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		
		List<AzRule> rules = null;
		
		if (this.localRules != null) {
			rules = this.localRules;
		} else {
			rules = holder.getAzRules();
		}
		
		ApplicationType at = new ApplicationType();
		at.setAzTimeoutMillis(3000L);
		
		boolean OK = az.checkRules(authData, holder.getConfig(), rules, session, at, null);
				
				
		
		if (OK) {
			String respGroup = az.getResponseSuccessGroup(holder);
			
			if (this.azSuccess != null) {
				respGroup = this.azSuccess;
			}
			
			AccessLog.log(AccessEvent.AzSuccess, holder.getApp(),  request.getServletRequest(), authData , respGroup != null ? respGroup : "NONE");
			if (respGroup != null) {
				az.processRequestResult(request.getServletRequest(), response.getServletResponse(), holder.getConfig().getResultGroup(respGroup),authData);
			}
			
			chain.nextFilter(request, response, chain);
			
			if (respGroup != null) {
				az.proccessResponseResult(request.getServletRequest(), response.getServletResponse(), holder.getConfig().getResultGroup(respGroup), false,authData,holder.getApp().getCookieConfig());
			}
		} else {
			String respGroup = az.getResponseFailGroup(holder);
			
			if (this.azFail != null) {
				respGroup = this.azFail;
			}
			
			AccessLog.log(AccessEvent.AzFail, holder.getApp(), request.getServletRequest(), authData , respGroup != null ? respGroup : "NONE");
			
			
			if (respGroup != null) {
				az.proccessResponseResult(request.getServletRequest(), response.getServletResponse(), holder.getConfig().getResultGroup(respGroup), true,authData, holder.getApp().getCookieConfig());
			} else {
				((HttpServletResponse) response).sendError(401);
			}
		}

	}

	@Override
	public void filterResponseText(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain,
			StringBuffer data) throws Exception {
		chain.nextFilterResponseText(request, response, chain, data);

	}

	@Override
	public void filterResponseBinary(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain, byte[] data,
			int length) throws Exception {
		chain.nextFilterResponseBinary(request, response, chain, data, length);

	}

	@Override
	public void initFilter(HttpFilterConfig config) throws Exception {
		this.az = new AzSys();
		
		Attribute rulesConfig = config.getAttribute("rules");
		
		if (rulesConfig != null) {
			this.localRules = new ArrayList<AzRule>();
			
			for (String val : rulesConfig.getValues()) {
				StringTokenizer toker = new StringTokenizer(val,";",false);
				toker.hasMoreTokens();
				String scope = toker.nextToken();
				toker.hasMoreTokens();
				String constraint = toker.nextToken();
				
				try {
					AzRule rule = new AzRule(scope,constraint,null,GlobalEntries.getGlobalEntries().getConfigManager(),null);
					this.localRules.add(rule);
				} catch (ProvisioningException e) {
					throw new ServletException("Could not create az rule",e);
				}
			}
		}
		
		Attribute azSuccessCfg = config.getAttribute("azSuccess");
		if (azSuccess != null) {
			this.azSuccess = azSuccessCfg.getValues().get(0);
		}
		
		Attribute azFailCfg = config.getAttribute("azFail");
		if (azFailCfg != null) {
			this.azFail = config.getAttribute("azFail").getValues().get(0);
		}

	}

}
