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
import java.util.HashMap;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.joda.time.DateTime;

import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.proxy.util.ProxyTools;
import com.tremolosecurity.saml.Attribute;



public class LoginService implements AuthMechanism {

	private static final String CHAINS = "chains";
	public static final String ORIG_REQ_HOLDER = "LOGIN_SERVICE_ORIG_REQ_HOLDER";
	
	

	@Override
	public void doGet(HttpServletRequest request, HttpServletResponse response,AuthStep as)
			throws IOException, ServletException {
		
		HttpSession session = ((HttpServletRequest) request).getSession();
		HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
		String cookieName = authParams.get("cookieName").getValues().get(0);
		int days = Integer.parseInt(authParams.get("cookieDays").getValues().get(0));
		
		
		Attribute chains = authParams.get(LoginService.CHAINS);
		
		HashMap<String,String> chainMap = new HashMap<String,String>();
		
		for (String val : chains.getValues()) {
			String chainLabel = val.substring(0,val.indexOf('='));
			String cahinURL = val.substring(val.indexOf('=') + 1);
			chainMap.put(chainLabel, cahinURL);
		}
		
		request.getSession().setAttribute(LoginService.CHAINS, chainMap);
		
		
		if (session.getAttribute("tremolo.io/loginservice/detination") != null) {
			String chainLabel = (String) session.getAttribute("tremolo.io/loginservice/detination");
			startLogin(request,response, session, chainMap, chainLabel,cookieName,days);
		} else if (chainMap.keySet().size() == 1) {
			String chainLabel = chainMap.keySet().iterator().next();
			startLogin(request,response, session, chainMap, chainLabel,cookieName,days);
		} else if (request.getParameter("chain") != null) {
			String chainLabel = request.getParameter("chain");
			startLogin(request,response, session, chainMap, chainLabel,cookieName,days);
			
		}  else {
			if (request.getCookies() != null) {
				for (Cookie cookie : request.getCookies()) {
					if (cookie.getName().equalsIgnoreCase(cookieName)) {
						String chainLabel = cookie.getValue();
						startLogin(request,response, session, chainMap, chainLabel,cookieName,days);
						return;
					}
				}
			}
			
			//request.getRequestDispatcher(authParams.get("serviceUrl").getValues().get(0)).forward(request, response);
			response.sendRedirect(ProxyTools.getInstance().getFqdnUrl(authParams.get("serviceUrl").getValues().get(0),request));
		}
		

	}

	private void startLogin(HttpServletRequest request,HttpServletResponse response, HttpSession session,
			HashMap<String, String> chainMap, String chainLabel,String cookieName,int days)
			throws IOException {
		String chainURL = chainMap.get(chainLabel);
		
		RequestHolder reqHolder = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
		session.setAttribute(LoginService.ORIG_REQ_HOLDER, reqHolder);
		
		//the authenticaiton process is "hijacked" by the login service
		((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getAuthSteps().clear();
		((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).setHolder(null);
		
		boolean found = false;
		if (request.getCookies() != null) {
			for (Cookie cookie : request.getCookies()) {
				if (cookie.getName().equalsIgnoreCase(cookieName)) {
					found = true;
				}
			}
		}
		
		if (! found) {
			if (request.getParameter("remember") != null && request.getParameter("remember").equalsIgnoreCase("true")) {
				Cookie cookie = new Cookie(cookieName,chainLabel);
				cookie.setPath("/");
				cookie.setMaxAge(days * 24 * 60 * 60);
				
				response.addCookie(cookie);
			}
		}
		
		response.sendRedirect(chainURL);
	}

	@Override
	public void doPost(HttpServletRequest request, HttpServletResponse response,AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response,as);

	}

	@Override
	public void doPut(HttpServletRequest request, HttpServletResponse response,AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);

	}

	@Override
	public void doHead(HttpServletRequest request, HttpServletResponse response,AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);

	}

	@Override
	public void doOptions(HttpServletRequest request,
			HttpServletResponse response,AuthStep as) throws IOException, ServletException {
		this.doGet(request, response, as);

	}

	@Override
	public void doDelete(HttpServletRequest request,
			HttpServletResponse response,AuthStep as) throws IOException, ServletException {
		this.doGet(request, response, as);

	}

	@Override
	public void init(ServletContext ctx, HashMap<String, Attribute> init) {
		

	}

	@Override
	public String getFinalURL(HttpServletRequest request,
			HttpServletResponse response) {
		return null;
	}

}
