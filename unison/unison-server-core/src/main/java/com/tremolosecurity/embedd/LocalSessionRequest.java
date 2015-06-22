/*
Copyright 2015 Tremolo Security, Inc.

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
import java.net.URLDecoder;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.StringTokenizer;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletInputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpSession;

import com.tremolosecurity.util.NVP;

public class LocalSessionRequest extends HttpServletRequestWrapper {

	HttpServletRequest req;
	
	List<NVP> queryString;
	
	public LocalSessionRequest(HttpServletRequest req) {
		super(req);
		this.req = req;
		this.queryString = new ArrayList<NVP>();
		if (req.getQueryString() != null && ! req.getQueryString().isEmpty()) {
			StringTokenizer toker = new StringTokenizer(req.getQueryString(),"&");
			while (toker.hasMoreTokens()) {
				String qp = toker.nextToken();
				int index = qp.indexOf('=');
				if (index > 0) {
					String name = qp.substring(0,qp.indexOf('='));
					String val;
					try {
						val = URLDecoder.decode(qp.substring(qp.indexOf('=') + 1),"UTf-8");
						this.queryString.add(new NVP(name,val));
					} catch (UnsupportedEncodingException e) {
						
					}
					
				}
			}
		}
	}
	
	@Override
	public Object getAttribute(String arg0) {
		return req.getAttribute(arg0);
	}

	@Override
	public Enumeration getAttributeNames() {
		return req.getAttributeNames();
	}

	@Override
	public String getCharacterEncoding() {
		return req.getCharacterEncoding();
	}

	@Override
	public int getContentLength() {
		return req.getContentLength();
	}

	@Override
	public String getContentType() {
		return req.getContentType();
	}

	@Override
	public ServletInputStream getInputStream() throws IOException {
		return req.getInputStream();
	}

	@Override
	public String getLocalAddr() {
		return req.getLocalAddr();
	}

	@Override
	public String getLocalName() {
		return req.getLocalName();
	}

	@Override
	public int getLocalPort() {
		return req.getLocalPort();
	}

	@Override
	public Locale getLocale() {
		return req.getLocale();
	}

	@Override
	public Enumeration getLocales() {
		return req.getLocales();
	}

	@Override
	public String getParameter(String arg0) {
		return req.getParameter(arg0);
	}

	@Override
	public Map getParameterMap() {
		return req.getParameterMap();
	}

	@Override
	public Enumeration getParameterNames() {
		return req.getParameterNames();
	}

	@Override
	public String[] getParameterValues(String arg0) {
		return req.getParameterValues(arg0);
	}

	@Override
	public String getProtocol() {
		return req.getProtocol();
	}

	@Override
	public BufferedReader getReader() throws IOException {
		return req.getReader();
	}

	@Override
	public String getRealPath(String arg0) {
		return req.getRealPath(arg0);
	}

	@Override
	public String getRemoteAddr() {
		return req.getRemoteAddr();
	}

	@Override
	public String getRemoteHost() {
		return req.getRemoteHost();
	}

	@Override
	public int getRemotePort() {
		return req.getRemotePort();
	}

	@Override
	public RequestDispatcher getRequestDispatcher(String arg0) {
		return req.getRequestDispatcher(arg0);
	}

	@Override
	public String getScheme() {
		return req.getScheme();
	}

	@Override
	public String getServerName() {
		return req.getServerName();
	}

	@Override
	public int getServerPort() {
		return req.getServerPort();
	}

	@Override
	public boolean isSecure() {
		return req.isSecure();
	}

	@Override
	public void removeAttribute(String arg0) {
		req.removeAttribute(arg0);
		
	}

	@Override
	public void setAttribute(String arg0, Object arg1) {
		req.setAttribute(arg0, arg1);
		
	}

	@Override
	public void setCharacterEncoding(String arg0)
			throws UnsupportedEncodingException {
		req.setCharacterEncoding(arg0);
		
	}

	@Override
	public String getAuthType() {
		return req.getAuthType();
	}

	@Override
	public String getContextPath() {
		return req.getContextPath();
	}

	@Override
	public Cookie[] getCookies() {
		return req.getCookies();
	}

	@Override
	public long getDateHeader(String arg0) {
		return req.getDateHeader(arg0);
	}

	@Override
	public String getHeader(String arg0) {
		return req.getHeader(arg0);
	}

	@Override
	public Enumeration getHeaderNames() {
		return req.getHeaderNames();
	}

	@Override
	public Enumeration getHeaders(String arg0) {
		return req.getHeaders(arg0);
	}

	@Override
	public int getIntHeader(String arg0) {
		return req.getIntHeader(arg0);
	}

	@Override
	public String getMethod() {
		return req.getMethod();
	}

	@Override
	public String getPathInfo() {
		return req.getPathInfo();
	}

	@Override
	public String getPathTranslated() {
		return req.getPathTranslated();
	}

	@Override
	public String getQueryString() {
		return req.getQueryString();
	}

	@Override
	public String getRemoteUser() {
		return req.getRemoteUser();
	}

	@Override
	public String getRequestURI() {
		return req.getRequestURI();
	}

	@Override
	public StringBuffer getRequestURL() {
		return req.getRequestURL();
	}

	@Override
	public String getRequestedSessionId() {
		return req.getRequestedSessionId();
	}

	@Override
	public String getServletPath() {
		return req.getServletPath();
	}

	@Override
	public HttpSession getSession() {
		String x = null;
		x.toString();
		return null;
	}

	@Override
	public HttpSession getSession(boolean arg0) {
		String x = null;
		x.toString();
		return null;
	}

	@Override
	public Principal getUserPrincipal() {
		return req.getUserPrincipal();
	}

	@Override
	public boolean isRequestedSessionIdFromCookie() {
		return true;
	}

	@Override
	public boolean isRequestedSessionIdFromURL() {
		return false;
	}

	@Override
	public boolean isRequestedSessionIdFromUrl() {
		return false;
	}

	@Override
	public boolean isRequestedSessionIdValid() {
		return true;
	}

	@Override
	public boolean isUserInRole(String arg0) {
		return req.isUserInRole(arg0);
	}

	public List<NVP> getQueryStringParams() {
		return this.queryString;
	}

}
