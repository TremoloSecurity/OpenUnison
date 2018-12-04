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


package com.tremolosecurity.embedd;

import java.io.IOException;
import java.util.HashMap;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.proxy.auth.AzSys;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterChainImpl;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterRequestImpl;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.filter.HttpFilterResponseImpl;
import com.tremolosecurity.proxy.util.NextSys;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;

public class EmbForward {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(EmbForward.class);
	
	public EmbForward() {
	
	}
	
	public void doEmbResults(HttpServletRequest request,HttpServletResponse response,FilterChain filterChain,NextSys nextSys) throws ServletException,IOException {
		
		ConfigManager cfg = (ConfigManager) request.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);
		if (((HttpServletRequest) request).getRequestURI().startsWith(cfg.getAuthPath())) {
			
			filterChain.doFilter(request, response);
			//nextSys.nextSys((HttpServletRequest) request, (HttpServletResponse) response);
			return;
		}
		
		boolean isText=false;
		
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		
		HttpFilterRequest filterReq = new HttpFilterRequestImpl(request,null);
		HttpFilterResponse filterResp = new HttpFilterResponseImpl(response);
		
		
		HttpFilterChain chain = new HttpFilterChainImpl(holder,new EmbPostProc(filterChain));
		try {
			chain.nextFilter(filterReq, filterResp, chain);
		} catch (Exception e) {
			logger.error("Error",e);
			throw new ServletException(e);
		}
		
		
	}
}
