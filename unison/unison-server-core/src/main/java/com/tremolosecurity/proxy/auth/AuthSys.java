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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;

import javax.servlet.FilterChain;
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
import com.tremolosecurity.log.AccessLog;
import com.tremolosecurity.log.AccessLog.AccessEvent;
import com.tremolosecurity.proxy.ProxyData;
import com.tremolosecurity.proxy.ProxySys;
import com.tremolosecurity.proxy.ProxyUtil;
import com.tremolosecurity.proxy.TremoloHttpSession;
import com.tremolosecurity.proxy.auth.sys.AuthManager;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.util.NextSys;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.proxy.util.ProxyTools;
import com.tremolosecurity.saml.Attribute;


public class AuthSys  {
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(AuthSys.class);
	
	@Deprecated
	public static final String AUTH_CTL = "TREMOLO_AUTH_CTL";

	//public static final String AUTH_DATA = "AUTO_IDM_AUTH_DATA";
	
	

	//public static final String AUTH_STEPS = "TREMOLO_AUTH_STEPS";

	//public static final String AUTH_CURR_STEP = "TREMOLO_CUR_STEP";
	
	
	@Deprecated
	public static StringBuffer getGetRedirectURL(RequestHolder reqHolder) {
		StringBuffer redirURL = new StringBuffer(reqHolder.getURL());

		if (reqHolder.isForceAuth() || redirURL.indexOf("?") > 0) {
			return redirURL;
		}

		Iterator<String> it = reqHolder.getParams().keySet().iterator();
		boolean first = true;

		while (it.hasNext()) {
			String key = it.next();
			Attribute attrib = reqHolder.getParams().get(key);

			Iterator<String> itvals = attrib.getValues().iterator();
			while (itvals.hasNext()) {
				String val = itvals.next();
				if (first) {
					first = false;
					redirURL.append('?').append(attrib.getName()).append('=')
							.append(URLEncoder.encode(val));
				} else {
					redirURL.append('&').append(attrib.getName()).append('=')
							.append(URLEncoder.encode(val));
				}
			}

		}
		return redirURL;
	}
	
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.auth.AuthSys#doAuth(javax.servlet.ServletRequest, javax.servlet.ServletResponse, com.tremolosecurity.proxy.util.NextSys)
	 */

	public void doAuth(ServletRequest req, ServletResponse resp,
			NextSys next) throws IOException, ServletException {
		req.setAttribute(AuthManager.NEXT_SYS, next);
		ConfigManager cfg = (ConfigManager) req.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);
		
		if (((HttpServletRequest) req).getRequestURI().startsWith(cfg.getAuthPath())) {
			next.nextSys((HttpServletRequest) req, (HttpServletResponse) resp);
			return;
		}
		
		HttpSession session = ((HttpServletRequest) req).getSession();
		
		AuthController actl = (AuthController) session.getAttribute(ProxyConstants.AUTH_CTL);
		
		
		
		
		UrlHolder holder = (UrlHolder) req.getAttribute(ProxyConstants.AUTOIDM_CFG);
		
		
		
		
		String urlChain = holder.getUrl().getAuthChain();
		AuthChainType act = holder.getConfig().getAuthChains().get(urlChain);
		
		
		
		if (urlChain == null) {
			//chain.doFilter(req, resp);
			next.nextSys((HttpServletRequest) req, (HttpServletResponse) resp);
			return;
		} 
		
		AuthInfo authData = actl.getAuthInfo();
		
		if (authData == null || ! authData.isAuthComplete()) {
			if (cfg.getAuthManager().nextAuth((HttpServletRequest) req,(HttpServletResponse) resp,session,false,next)) {
				next.nextSys((HttpServletRequest) req, (HttpServletResponse) resp);
			}
		} else {
			if (authData.getAuthLevel() < act.getLevel()) {
				//step up authentication, clear existing auth data
				
				session.removeAttribute(ProxyConstants.AUTH_CTL);
				
				holder.getConfig().createAnonUser(session);
				
				cfg.getAuthManager().nextAuth((HttpServletRequest) req,(HttpServletResponse) resp,session,false,next);
			} else {
				//chain.doFilter(req, resp);
				next.nextSys((HttpServletRequest) req, (HttpServletResponse) resp);
			}
		}
	}

}
