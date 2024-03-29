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


package com.tremolosecurity.proxy.auth;

import java.io.IOException;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.MechanismType;


import com.tremolosecurity.proxy.TremoloHttpSession;
import com.tremolosecurity.proxy.auth.RequestHolder.HTTPMethod;
import com.tremolosecurity.proxy.filter.HttpFilterRequestImpl;
import com.tremolosecurity.proxy.util.FilterNextSys;
import com.tremolosecurity.proxy.util.NextSys;

public class AuthFilter implements Filter {

	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(AuthFilter.class);
	
	static String authFilterURI;
	AuthSys authMgr;
	
	@Override
	public void destroy() {
		// TODO Auto-generated method stub

	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp,
			FilterChain chain) throws IOException, ServletException {
		
		 
		
		//HttpSession session = ((HttpServletRequest) req).getSession(true);
		
		//SharedSession.getSharedSession().registerSession(session);
		
		//HttpSession session = (HttpSession) req.getAttribute(ConfigFilter.AUTOIDM_SESSION);//((HttpServletRequest) req).getSession();
		NextSys next = new FilterNextSys(chain);
		authMgr.doAuth(req, resp, next);

	}

	
	
	@Override
	public void init(FilterConfig conf) throws ServletException {
		this.authMgr = new AuthSys();
		
	}

}
