/*******************************************************************************
 * Copyright 2016, 2018 Tremolo Security, Inc.
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
package com.tremolosecurity.scalejs.token.ws;

import java.util.HashMap;

import org.apache.logging.log4j.Logger;

import com.google.gson.Gson;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;

import com.tremolosecurity.scalejs.token.cfg.ScaleTokenConfig;
import com.tremolosecurity.scalejs.token.data.ScaleTokenUser;
import com.tremolosecurity.scalejs.token.sdk.TokenLoader;
import com.tremolosecurity.scalejs.util.ScaleJSUtils;

public class ScaleToken implements HttpFilter {
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(ScaleToken.class.getName());
	ScaleTokenConfig scaleConfig;
	TokenLoader tokenLoader;
	
	@Override
	public void doFilter(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		Gson gson = new Gson();
		
		
		
		request.getServletRequest().setAttribute("com.tremolosecurity.unison.proxy.noRedirectOnError", "com.tremolosecurity.unison.proxy.noRedirectOnError");
		
		if (request.getRequestURI().endsWith("/token/config")) {
			response.setContentType("application/json; charset=UTF-8");
			ScaleJSUtils.addCacheHeaders(response);
			response.getWriter().println(gson.toJson(scaleConfig).trim());
		} else if (request.getMethod().equalsIgnoreCase("GET") && request.getRequestURI().endsWith("/token/user")) {
			AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
			ScaleTokenUser stu = new ScaleTokenUser();
			Attribute displayNameAttribute = userData.getAttribs().get(this.scaleConfig.getDisplayNameAttribute());
			if (displayNameAttribute != null) {
				stu.setDisplayName(displayNameAttribute.getValues().get(0));
			} else {
				stu.setDisplayName("Unknown");
			}
			
			stu.setToken(this.tokenLoader.loadToken(userData, request.getSession()));
			ScaleJSUtils.addCacheHeaders(response);
			response.setContentType("application/json; charset=UTF-8");
			response.getWriter().println(gson.toJson(stu).trim());
		}

	}

	@Override
	public void filterResponseText(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain,
			StringBuffer data) throws Exception {
		

	}

	@Override
	public void filterResponseBinary(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain,
			byte[] data, int length) throws Exception {
		

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
	
	@Override
	public void initFilter(HttpFilterConfig config) throws Exception {
		this.scaleConfig = new ScaleTokenConfig();
		scaleConfig.setDisplayNameAttribute(this.loadAttributeValue("displayNameAttribute", "Display Name Attribute Name", config));
		scaleConfig.getFrontPage().setTitle(this.loadAttributeValue("frontPage.title", "Front Page Title", config));
		scaleConfig.getFrontPage().setText(this.loadAttributeValue("frontPage.text", "Front Page Text", config));
		scaleConfig.setHomeURL(this.loadAttributeValue("homeURL", "Home URL", config));
		scaleConfig.setLogoutURL(this.loadAttributeValue("logoutURL", "Logout URL", config));
		scaleConfig.setQrCodeAttribute(this.loadOptionalAttributeValue("qrCodeAttribute", "QR Code Attribute", config));
		scaleConfig.setWarnMinutesLeft(Integer.parseInt(this.loadAttributeValue("warnMinutesLeft", "Warn when number of minutes left in the user's session", config)));
		
		String tokenClassName = this.loadAttributeValue("tokenClassName", "Token Class Name", config);
		this.tokenLoader = (TokenLoader) Class.forName(tokenClassName).newInstance();
		this.tokenLoader.init(config,scaleConfig);
		
		
		

	}

}
