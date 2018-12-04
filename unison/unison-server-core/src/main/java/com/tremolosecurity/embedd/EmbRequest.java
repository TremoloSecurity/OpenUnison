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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Principal;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.Vector;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletInputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpSession;

import org.apache.logging.log4j.Logger;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.filter.AutoIDMPrincipal;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.auth.AzSys;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.util.ItEnumeration;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;

public class EmbRequest extends HttpServletRequestWrapper {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(EmbRequest.class);

	private static final DateTimeFormatter RFC1123_DATE_TIME_FORMATTER = 
		    DateTimeFormat.forPattern("EEE, dd MMM yyyy HH:mm:ss 'GMT'")
		    .withZoneUTC();
	
	HttpServletRequest request;
	public HttpServletRequest getRequest() {
		return request;
	}

	HttpSession session;
	
	HashMap<String,Attribute> headers;
	HashMap<String,String> headerMap;
	
	String userPrincipal;
	HashSet<String> roles;
	
	public EmbRequest(HttpFilterRequest filterReq,HttpSession session,HashMap<String,Attribute> reqHeaders) {
		super(filterReq.getServletRequest());
		HttpServletRequest req = filterReq.getServletRequest();
		this.request = req;
		this.session = session;
		
		this.headers = reqHeaders;
		this.headerMap = new HashMap<String,String>();
		
		
		for (String key : this.headers.keySet()) {
			this.headerMap.put(key.toLowerCase(), key);
		}
		
		if (this.headers == null) {
			this.headers = new HashMap<String,Attribute>();
		}
		
		
		
		
		ConfigManager cfg = (ConfigManager) req.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);
		if (cfg.getPaasUserPrinicipalAttribute() != null) {
			AuthInfo authData = ((AuthController) ((HttpServletRequest) request).getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
			Attribute attr = authData.getAttribs().get(cfg.getPaasUserPrinicipalAttribute());
			if (attr != null) {
				this.userPrincipal = attr.getValues().get(0);
			}
		}
		
		if (cfg.getPaasRoleAttribute() != null) {
			AuthInfo authData = ((AuthController) ((HttpServletRequest) request).getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
			Attribute attr = authData.getAttribs().get(cfg.getPaasRoleAttribute());
			if (attr != null) {
				this.roles = new HashSet<String>();
				this.roles.addAll(attr.getValues());
			}
		}
		
		
	}
	
	@Override
	public String getLocalAddr() {
		return request.getLocalAddr();
	}

	@Override
	public String getLocalName() {
		return request.getLocalName();
	}

	@Override
	public int getLocalPort() {
		return request.getLocalPort();
	}

	@Override
	public int getRemotePort() {
		return request.getRemotePort();
	}
	@Override
	public String getAuthType() {
		return request.getAuthType();
	}

	@Override
	public String getContextPath() {
		return request.getContextPath();
	}

	@Override
	public Cookie[] getCookies() {
		return request.getCookies();
	}

	@Override
	public long getDateHeader(String name) {
		name = this.headerMap.get(name.toLowerCase());
		if (name != null) {
			if (Character.isDigit(headers.get(name).getValues().get(0).charAt(0))) {
				return Long.parseLong(headers.get(name).getValues().get(0).toString());
			} else {
				return RFC1123_DATE_TIME_FORMATTER.parseDateTime(headers.get(name).getValues().get(0).toString()).getMillis();
			}
		} else {
			return -1;
		}
	}

	@Override
	public String getHeader(String name) {
		
		name = this.headerMap.get(name.toLowerCase());
		
		if (name != null) {
			return headers.get(name).getValues().get(0).toString();
		} else {
			return null;
		}
	}

	@Override
	public Enumeration getHeaderNames() {
		return new ItEnumeration(this.headers.keySet().iterator());
	}

	@Override
	public Enumeration getHeaders(String name) {
		
		name = this.headerMap.get(name.toLowerCase());
		
		
		
		if (name != null) {
			
			return new ItEnumeration(this.headers.get(name).getValues().iterator());
		} else {
			
			return null;
		}
	}

	@Override
	public int getIntHeader(String name) {
		name = this.headerMap.get(name.toLowerCase());
		return Integer.parseInt(headers.get(name).getValues().get(0).toString());
	}

	@Override
	public String getMethod() {
		return request.getMethod();
	}

	@Override
	public String getPathInfo() {
		return request.getPathInfo();
	}

	@Override
	public String getPathTranslated() {
		return request.getPathTranslated();
	}

	@Override
	public String getQueryString() {
		return request.getQueryString();
	}

	@Override
	public String getRemoteUser() {
		return this.userPrincipal;
	}

	@Override
	public String getRequestURI() {
		return request.getRequestURI();
	}

	@Override
	public StringBuffer getRequestURL() {
		return request.getRequestURL();
	}

	@Override
	public String getRequestedSessionId() {
		return request.getRequestedSessionId();
		
	}

	@Override
	public String getServletPath() {
		return request.getServletPath();
	}

	@Override
	public HttpSession getSession() {
		
		return this.session;
	}

	@Override
	public HttpSession getSession(boolean arg0) {
		return this.session;
	}

	@Override
	public Principal getUserPrincipal() {
		if (this.userPrincipal != null) {
			AuthInfo authData = ((AuthController) ((HttpServletRequest) request).getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
			return new AutoIDMPrincipal(this.userPrincipal,authData.getAttribs());
		} else {
			return null;
		}
		
	}

	@Override
	public boolean isRequestedSessionIdFromCookie() {
		return request.isRequestedSessionIdFromCookie();
	}

	@Override
	public boolean isRequestedSessionIdFromURL() {
		return request.isRequestedSessionIdFromURL();
	}

	@Override
	public boolean isRequestedSessionIdFromUrl() {
		return request.isRequestedSessionIdFromUrl();
	}

	@Override
	public boolean isRequestedSessionIdValid() {
		return request.isRequestedSessionIdValid();
	}

	@Override
	public boolean isUserInRole(String role) {
		if (this.roles != null) {
			return this.roles.contains(role);
		} else {
			return false;
		}
	}

	@Override
	public Object getAttribute(String arg0) {
		return request.getAttribute(arg0);
	}

	@Override
	public Enumeration getAttributeNames() {
		return request.getAttributeNames();
	}

	@Override
	public String getCharacterEncoding() {
		return request.getCharacterEncoding();
	}

	@Override
	public int getContentLength() {
		return request.getContentLength();
	}

	@Override
	public String getContentType() {
		return request.getContentType();
	}
	

	@Override
	public ServletInputStream getInputStream() throws IOException {
		return request.getInputStream();
	}

	@Override
	public Locale getLocale() {
		return request.getLocale();
	}

	@Override
	public Enumeration getLocales() {
		return request.getLocales();
	}

	@Override
	public String getParameter(String arg0) {
		
		return request.getParameter(arg0);
	}

	@Override
	public Map getParameterMap() {
		return request.getParameterMap();
	}

	@Override
	public Enumeration getParameterNames() {
		return request.getParameterNames();
	}

	@Override
	public String[] getParameterValues(String arg0) {
		
		return request.getParameterValues(arg0);
	}

	@Override
	public String getProtocol() {
		return request.getProtocol();
	}

	@Override
	public BufferedReader getReader() throws IOException {
		return request.getReader();
	}

	@Override
	public String getRealPath(String arg0) {
		return request.getRealPath(arg0);
	}

	@Override
	public String getRemoteAddr() {
		return request.getRemoteAddr();
	}

	@Override
	public String getRemoteHost() {
		return request.getRemoteHost();
	}

	@Override
	public RequestDispatcher getRequestDispatcher(String arg0) {
		return request.getRequestDispatcher(arg0);
	}

	@Override
	public String getScheme() {
		return request.getScheme();
	}

	@Override
	public String getServerName() {
		return request.getServerName();
	}

	@Override
	public int getServerPort() {
		return request.getServerPort();
	}

	@Override
	public boolean isSecure() {
		return request.isSecure();
	}

	@Override
	public void removeAttribute(String arg0) {
		request.removeAttribute(arg0);

	}

	@Override
	public void setAttribute(String arg0, Object arg1) {
		request.setAttribute(arg0, arg1);

	}

	@Override
	public void setCharacterEncoding(String arg0)
			throws UnsupportedEncodingException {
		request.setCharacterEncoding(arg0);

	}

}
