/*******************************************************************************
 * Copyright (c) 2021 Tremolo Security, Inc.
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
package com.tremolosecurity.proxy.auth;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import com.tremolosecurity.proxy.mappings.JavaScriptMappings;
import com.tremolosecurity.server.GlobalEntries;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.apache.log4j.Logger;
import org.graalvm.polyglot.Context;
import org.graalvm.polyglot.Value;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;

public class JavaScriptAuth implements AuthMechanism {
	static Logger logger = Logger.getLogger(JavaScriptAuth.class.getName());

	@Override
	public void init(ServletContext ctx, HashMap<String, Attribute> init) {
		

	}

	@Override
	public String getFinalURL(HttpServletRequest request, HttpServletResponse response) {
		
		return null;
	}

	@Override
	public void doGet(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		HttpSession session = ((HttpServletRequest) request).getSession();
		HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);

		Context context = Context.newBuilder("js").allowAllAccess(true).build();

		if (authParams.containsKey("includeJs")) {
			Attribute jsToLoadAttr = authParams.get("includeJs");
			JavaScriptMappings javascripts = (JavaScriptMappings) GlobalEntries.getGlobalEntries().get("javascripts");
			if (javascripts != null) {
				for (String jsName : jsToLoadAttr.getValues()) {
					String javascript = javascripts.getMapping(jsName);
					if (javascript != null) {
						context.eval("js", javascript);
					} else {
						logger.warn("JavScript " + jsName + " not found");
					}
				}
			} else {
				logger.warn("No javascripts loader initialized");
			}
		}
		
		String js = authParams.get("js").getValues().get(0);

		
		Value val = context.eval("js",js);
		
		Value doAuth = context.getBindings("js").getMember("doAuth");
		
		if (doAuth == null || ! doAuth.canExecute()) {
			throw new ServletException("doAuth function must be defined with three parameters and must be void");
		}
		
		doAuth.execute(request,response,as);

	}

	@Override
	public void doPost(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);

	}

	@Override
	public void doPut(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);

	}

	@Override
	public void doHead(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);

	}

	@Override
	public void doOptions(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);

	}

	@Override
	public void doDelete(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);

	}

}
