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


package com.tremolosecurity.filter;

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
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;

import com.tremolosecurity.saml.Attribute;


/**
 * @author mlb
 *
 */
public class AutoIDMRequest implements HttpServletRequest {

	static Logger logger = Logger.getLogger(AutoIDMRequest.class);
	
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

	HttpServletRequest request;
	com.tremolosecurity.lastmile.LastMile lastmile;
	HashMap<String,Vector<String>> headers;
	String userAttribute;
	HashMap<String,com.tremolosecurity.saml.Attribute> attribs;
	HashSet<String> roles;
	
	public AutoIDMRequest(HttpServletRequest request,com.tremolosecurity.lastmile.LastMile lastmile,String userAttribute,String roleAttribute,boolean toHeaders) {
		this.request = request;
		this.lastmile = lastmile;
		this.userAttribute = userAttribute;
		this.headers = new HashMap<String,Vector<String>>();
		this.attribs = new HashMap<String,Attribute>();
		this.roles = new HashSet<String>();
		
		Enumeration headerNames = request.getHeaderNames();
		while (headerNames.hasMoreElements()) {
			String name = (String) headerNames.nextElement();
			Vector<String> vals = new Vector<String>();
			Enumeration enumvals = request.getHeaders(name);
			while (enumvals.hasMoreElements()) {
				String val = (String) enumvals.nextElement(); 
				//if (logger.isDebugEnabled()) {
					////System.out.println("Header From Assertion : " + name + "='" + val + "'");
				//}
				
				vals.add(val);
			}
			this.headers.put(name, vals);
			
		}
		
		
		Iterator<Attribute> attribs = lastmile.getAttributes().iterator();
		while (attribs.hasNext()) {
			Attribute attrib = attribs.next();
			if (toHeaders) {
				
				Vector<String> vals = this.headers.get(attrib.getName());
				if (vals == null) {
					vals = new Vector<String>();
					this.headers.put(attrib.getName(), vals);
				}
				vals.addAll(attrib.getValues());
			}
			
			this.attribs.put(attrib.getName(), attrib);
			
			if (attrib.getName().equals(roleAttribute)) {
				this.roles.addAll(attrib.getValues());
			}
		}
			
		
	}
	
	@Override
	public String getAuthType() {
		return "";
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
		
		if (logger.isDebugEnabled()) {
			logger.debug("Header Requested : '" + name + "'" );
		}
		
		if (! this.headers.containsKey(name)) {
			return -1;
		} else {
			return Long.parseLong(this.headers.get(name).get(0));
		}
	}

	@Override
	public String getHeader(String name) {
		
		if (logger.isDebugEnabled()) {
			logger.debug("Header Requested : '" + name + "'" );
		}
		
		if (! this.headers.containsKey(name)) {
			return null;
		} else {
			return this.headers.get(name).get(0);
		}
	}

	@Override
	public Enumeration getHeaderNames() {
		Vector names = new Vector();
		names.addAll(this.headers.keySet());
		return names.elements();
	}

	@Override
	public Enumeration getHeaders(String name) {
		if (! this.headers.containsKey(name)) {
			return null;
		} else {
			return this.headers.get(name).elements();
		}
	}

	@Override
	public int getIntHeader(String name) {
		if (! this.headers.containsKey(name)) {
			return 0;
		} else {
			return Integer.parseInt(this.headers.get(name).get(0));
		}
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
		return this.attribs.get(this.userAttribute).getValues().get(0);
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
		return request.getSession();
	}

	@Override
	public HttpSession getSession(boolean arg0) {
		return request.getSession(arg0);
	}

	@Override
	public Principal getUserPrincipal() {
		if (this.attribs.get(this.userAttribute) != null) {
			return new AutoIDMPrincipal(this.attribs.get(this.userAttribute).getValues().get(0),this.attribs);
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
		return this.roles.contains(role);
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
