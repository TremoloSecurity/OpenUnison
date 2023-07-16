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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.config.util.UnisonConfigManagerImpl;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.MechanismType;
import com.tremolosecurity.config.xml.ParamType;
import com.tremolosecurity.config.xml.ResultGroupType;
import com.tremolosecurity.config.xml.ResultType;

import com.tremolosecurity.proxy.ConfigSys;
import com.tremolosecurity.proxy.TremoloHttpSession;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.util.FilterNextSys;
import com.tremolosecurity.proxy.util.NextSys;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.proxy.util.ProxyTools;
import com.tremolosecurity.saml.Attribute;

public class AuthMechMgr implements Filter {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(AuthMechMgr.class);
	
	AuthMgrSys sys;
	
	@Override
	public void destroy() {
		// TODO Auto-generated method stub

	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp,
			FilterChain chain) throws IOException, ServletException {
		
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		
		AuthController ac = (AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL);
		
		
		AuthStep curStep = ac.getCurrentStep();
		if (curStep != null) {
			curStep.setExecuted(true);
			curStep.setSuccess(false);
		}
		
		NextSys next = new FilterNextSys(chain);
		sys.doAuthMgr(request, response, next,curStep);
		
		
	}

	@Override
	public void init(FilterConfig cfg) throws ServletException {
		this.sys = new AuthMgrSys(cfg.getServletContext());
	}

	
}
