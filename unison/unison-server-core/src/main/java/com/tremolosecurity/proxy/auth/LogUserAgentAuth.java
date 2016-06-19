/*******************************************************************************
 * Copyright 2016 Tremolo Security, Inc.
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
package com.tremolosecurity.proxy.auth;

import java.io.IOException;
import java.util.HashMap;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;

public class LogUserAgentAuth implements AuthMechanism {

	
	static Logger logger = Logger.getLogger(LogUserAgentAuth.class);
	
	public void doDelete(HttpServletRequest request, HttpServletResponse response, AuthStep step)
			throws IOException, ServletException {
		doGet(request,response,step);

	}

	public void doGet(HttpServletRequest request, HttpServletResponse response, AuthStep step)
			throws IOException, ServletException {
		String header = request.getHeader("User-Agent");
		if (header == null) {
			header = request.getHeader("user-agent");
		}
		
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		if (holder == null) {
			throw new ServletException("Holder is null");
		}
		
		if (header == null) {
			logger.warn("No user agent");
		} else {
			AuthController ac = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL));
			
			StringBuffer b = new StringBuffer();
			b.append("dn='");
			
			if (ac == null) {
				b.append("No User");
			} else {
				b.append(ac.getAuthInfo().getUserDN());
			}
			
			b.append("' - '").append(header).append("'");
			
			logger.info(b.toString());
		}
		
		step.setSuccess(true);
		holder.getConfig().getAuthManager().nextAuth(request, response,request.getSession(),false);

	}

	public void doHead(HttpServletRequest request, HttpServletResponse response, AuthStep step)
			throws IOException, ServletException {
		doGet(request,response,step);

	}

	public void doOptions(HttpServletRequest request, HttpServletResponse response, AuthStep step)
			throws IOException, ServletException {
		doGet(request,response,step);

	}

	public void doPost(HttpServletRequest request, HttpServletResponse response, AuthStep step)
			throws IOException, ServletException {
		doGet(request,response,step);

	}

	public void doPut(HttpServletRequest request, HttpServletResponse response, AuthStep step)
			throws IOException, ServletException {
		doGet(request,response,step);

	}

	public String getFinalURL(HttpServletRequest request, HttpServletResponse response) {
		
		return null;
	}

	public void init(ServletContext ctx, HashMap<String, Attribute> params) {
		

	}

}
