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
import javax.servlet.http.HttpSession;

import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;

public class MappingAuthmech implements AuthMechanism {

	public void doDelete(HttpServletRequest request, HttpServletResponse response, AuthStep step)
			throws IOException, ServletException {
		this.doGet(request, response, step);

	}

	public void doGet(HttpServletRequest request, HttpServletResponse response, AuthStep step)
			throws IOException, ServletException {
		HttpSession session = ((HttpServletRequest) request).getSession(); 
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		if (holder == null) {
			throw new ServletException("Holder is null");
		}
		
		RequestHolder reqHolder = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
		
		HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
		
		Attribute map = authParams.get("map");
		for (String mapping : map.getValues()) {
			String newName = mapping.substring(0,mapping.indexOf('='));
			String oldName = mapping.substring(mapping.indexOf('=') + 1);
			
			AuthController ac = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL));
			Attribute attr = ac.getAuthInfo().getAttribs().get(oldName);
			Attribute newAttr = new Attribute(newName);
			newAttr.getValues().addAll(attr.getValues());
			
			ac.getAuthInfo().getAttribs().remove(oldName);
			ac.getAuthInfo().getAttribs().put(newName, newAttr);
		}

		step.setSuccess(true);
		holder.getConfig().getAuthManager().nextAuth(request, response,session,false);
	}

	public void doHead(HttpServletRequest request, HttpServletResponse response, AuthStep step)
			throws IOException, ServletException {
		this.doGet(request, response, step);

	}

	public void doOptions(HttpServletRequest request, HttpServletResponse response, AuthStep step)
			throws IOException, ServletException {
		this.doGet(request, response, step);

	}

	public void doPost(HttpServletRequest request, HttpServletResponse response, AuthStep step)
			throws IOException, ServletException {
		this.doGet(request, response, step);

	}

	public void doPut(HttpServletRequest request, HttpServletResponse response, AuthStep step)
			throws IOException, ServletException {
		this.doGet(request, response, step);

	}

	public String getFinalURL(HttpServletRequest request, HttpServletResponse response) {
	
		return null;
	}

	public void init(ServletContext context, HashMap<String, Attribute> config) {
		

	}

}
