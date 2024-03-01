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


package com.tremolosecurity.proxy.filter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.Vector;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import org.apache.commons.fileupload2.core.FileItem;
import org.apache.http.message.BasicHeader;
import org.apache.logging.log4j.Logger;


import com.tremolosecurity.proxy.ProxyRequest;
import com.tremolosecurity.proxy.ProxyUtil;

import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.util.NVP;


public class HttpFilterRequestImpl implements HttpFilterRequest  {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(HttpFilterRequestImpl.class);
	
	HttpServletRequest request;
	
	
	
	HashMap<String,com.tremolosecurity.saml.Attribute> headers;
	HashMap<String,com.tremolosecurity.saml.Attribute> params;
	ArrayList<String> paramNames;
	HashMap<String,ArrayList<Cookie>> cookies;
	
	AuthInfo authInfo;
	
	
	public HttpFilterRequestImpl(HttpServletRequest request,AuthInfo authInfo) {
		this.request = request;
		
		this.headers = new HashMap<String,Attribute>();
		this.cookies = new HashMap<String,ArrayList<Cookie>>();
		this.params = new HashMap<String,Attribute>();
		this.paramNames = new ArrayList<String>();
		
		Enumeration enumer = request.getParameterNames();
		while (enumer.hasMoreElements()) {
			String name = (String) enumer.nextElement();
			this.paramNames.add(name);
		}
		
		
		this.authInfo = authInfo;
		
		boolean first = true;
		
		ProxyUtil.loadParams(request,this.params);
		
		enumer = request.getHeaderNames();
		while (enumer.hasMoreElements()) {
			String name = (String) enumer.nextElement();
			Enumeration enumerVals = request.getHeaders(name);
			Attribute attrib = new Attribute(name);
			this.headers.put(attrib.getName().toLowerCase(), attrib);
			while (enumerVals.hasMoreElements()) {
				attrib.getValues().add((String) enumerVals.nextElement());
			}
		}
		
		Cookie[] cookies = request.getCookies();
		if (cookies == null) {
			cookies = new Cookie[0];
		}
		for (int i=0;i<cookies.length;i++) {
			ArrayList<Cookie> cookieList = this.cookies.get(cookies[i].getName());
			if (cookieList == null) {
				cookieList = new ArrayList<Cookie>();
				this.cookies.put(cookies[i].getName(), cookieList);
			}
			cookieList.add(cookies[i]);
			
		}
			
		
	}

	
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#getAuthInfo()
	 */
	@Override
	public AuthInfo getAuthInfo() {
		return ((AuthController) this.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#getContextPath()
	 */
	@Override
	public String getContextPath() {
		return request.getContextPath();
	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#getCookieNames()
	 */
	@Override
	public Set<String> getCookieNames() {
		return this.cookies.keySet();
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#getCookies(java.lang.String)
	 */
	@Override
	public ArrayList<Cookie> getCookies(String name) {
		return this.cookies.get(name);
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#addCookie(jakarta.servlet.http.Cookie)
	 */
	@Override
	public void addCookie(Cookie cookie) {
		ArrayList<Cookie> vals = this.cookies.get(cookie.getName());
		if (vals == null) {
			vals = new ArrayList<Cookie>();
			this.cookies.put(cookie.getName(), vals);
		}
		vals.add(cookie);
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#removeCookie(java.lang.String)
	 */
	@Override
	public void removeCookie(String name) {
		
		this.cookies.remove(name);
		
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#getHeaderNames()
	 */
	@Override
	public Iterator<String> getHeaderNames() {
		
		ArrayList<String> headerNamesWithCase = new ArrayList<String>();
		
		for (String name : this.headers.keySet()) {
			headerNamesWithCase.add(this.headers.get(name).getName());
		}
		
		return headerNamesWithCase.iterator();
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#getHeader(java.lang.String)
	 */
	@Override
	public Attribute getHeader(String name) {
		return this.headers.get(name.toLowerCase());
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#addHeader(com.tremolosecurity.saml.Attribute)
	 */
	@Override
	public void addHeader(Attribute header) {
		Attribute curHeader = this.headers.get(header.getName().toLowerCase());
		if (curHeader != null) {
			curHeader.getValues().addAll(header.getValues());
		} else {
			this.headers.put(header.getName().toLowerCase(), header);
		}
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#removeHeader(java.lang.String)
	 */
	@Override
	public void removeHeader(String name) {
		this.headers.remove(name.toLowerCase());
	}
	

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#getMethod()
	 */
	@Override
	public String getMethod() {
		return request.getMethod();
	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#getPathInfo()
	 */
	@Override
	public String getPathInfo() {
		return request.getPathInfo();
	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#getPathTranslated()
	 */
	@Override
	public String getPathTranslated() {
		return request.getPathTranslated();
	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#getQueryString()
	 */
	@Override
	public String getQueryString() {
		return request.getQueryString();
	}

	
	

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#getRequestURI()
	 */
	@Override
	public String getRequestURI() {
		return request.getRequestURI();
	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#getRequestURL()
	 */
	@Override
	public StringBuffer getRequestURL() {
		return request.getRequestURL();
	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#getRequestedSessionId()
	 */
	@Override
	public String getRequestedSessionId() {
		return request.getRequestedSessionId();
		
	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#getServletPath()
	 */
	@Override
	public String getServletPath() {
		return request.getServletPath();
	}


	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#getSession()
	 */
	@Override
	public HttpSession getSession() {
		return request.getSession();
	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#getSession(boolean)
	 */
	@Override
	public HttpSession getSession(boolean arg0) {
		return request.getSession(arg0);
	}

	
	
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#isRequestedSessionIdFromCookie()
	 */
	@Override
	public boolean isRequestedSessionIdFromCookie() {
		return request.isRequestedSessionIdFromCookie();
	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#isRequestedSessionIdFromURL()
	 */
	@Override
	public boolean isRequestedSessionIdFromURL() {
		return request.isRequestedSessionIdFromURL();
	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#isRequestedSessionIdFromUrl()
	 */
	@Override
	public boolean isRequestedSessionIdFromUrl() {
		return request.isRequestedSessionIdFromURL();
	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#isRequestedSessionIdValid()
	 */
	@Override
	public boolean isRequestedSessionIdValid() {
		return request.isRequestedSessionIdValid();
	}

	

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#getAttribute(java.lang.String)
	 */
	@Override
	public Object getAttribute(String arg0) {
		return request.getAttribute(arg0);
	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#getAttributeNames()
	 */
	@Override
	public Enumeration getAttributeNames() {
		return request.getAttributeNames();
	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#getCharacterEncoding()
	 */
	@Override
	public String getCharacterEncoding() {
		return request.getCharacterEncoding();
	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#getContentLength()
	 */
	@Override
	public int getContentLength() {
		return request.getContentLength();
	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#getContentType()
	 */
	@Override
	public String getContentType() {
		return request.getContentType();
	}
	

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#getInputStream()
	 */
	@Override
	public ServletInputStream getInputStream() throws IOException {
		return request.getInputStream();
	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#getLocale()
	 */
	@Override
	public Locale getLocale() {
		return request.getLocale();
	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#getLocales()
	 */
	@Override
	public Enumeration getLocales() {
		return request.getLocales();
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#getParameterNames()
	 */
	@Override
	public Iterator<String> getParameterNames() {
		return this.paramNames.iterator();
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#getParameter(java.lang.String)
	 */
	@Override
	public Attribute getParameter(String name) {
		return this.params.get(name);
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#addParameter(com.tremolosecurity.saml.Attribute)
	 */
	@Override
	public void addParameter(Attribute attrib) {
		if (this.params.containsKey(attrib.getName())) {
			this.params.get(attrib.getName()).getValues().addAll(attrib.getValues());
		} else {
			this.params.put(attrib.getName(), attrib);
		}
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#removeParameter(java.lang.String)
	 */
	@Override
	public void removeParameter(String name) {
		this.params.remove(name);
	}

	

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#getProtocol()
	 */
	@Override
	public String getProtocol() {
		return request.getProtocol();
	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#getReader()
	 */
	@Override
	public BufferedReader getReader() throws IOException {
		return request.getReader();
	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#getRealPath(java.lang.String)
	 */
	@Override
	public String getRealPath(String arg0) {
		return request.getSession().getServletContext().getRealPath(arg0);
	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#getRemoteAddr()
	 */
	@Override
	public String getRemoteAddr() {
		return request.getRemoteAddr();
	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#getRemoteHost()
	 */
	@Override
	public String getRemoteHost() {
		return request.getRemoteHost();
	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#getRequestDispatcher(java.lang.String)
	 */
	@Override
	public RequestDispatcher getRequestDispatcher(String arg0) {
		return request.getRequestDispatcher(arg0);
	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#getScheme()
	 */
	@Override
	public String getScheme() {
		return request.getScheme();
	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#getServerName()
	 */
	@Override
	public String getServerName() {
		return request.getServerName();
	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#getServerPort()
	 */
	@Override
	public int getServerPort() {
		return request.getServerPort();
	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#isSecure()
	 */
	@Override
	public boolean isSecure() {
		return request.isSecure();
	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#removeAttribute(java.lang.String)
	 */
	@Override
	public void removeAttribute(String arg0) {
		request.removeAttribute(arg0);

	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#setAttribute(java.lang.String, java.lang.Object)
	 */
	@Override
	public void setAttribute(String arg0, Object arg1) {
		request.setAttribute(arg0, arg1);

	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#setCharacterEncoding(java.lang.String)
	 */
	@Override
	public void setCharacterEncoding(String arg0)
			throws UnsupportedEncodingException {
		request.setCharacterEncoding(arg0);

	}


	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#isMultiPart()
	 */
	@Override
	public boolean isMultiPart() {
		return ((ProxyRequest) this.request).isMultiPart();
	}
	
	
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#isParamsInBody()
	 */
	@Override
	public boolean isParamsInBody() {
		return ((ProxyRequest) this.request).isParamsInBody();
	}
	
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#getFiles()
	 */
	@Override
	public HashMap<String,ArrayList<FileItem>> getFiles() {
		return ((ProxyRequest) this.request).getFiles(); 
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#getServletRequest()
	 */
	@Override
	public HttpServletRequest getServletRequest() {
		return this.request;
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterRequest#renameAttribute(java.lang.String, java.lang.String)
	 */
	@Override
	public void renameAttribute(String oldName,String newName) {
		Attribute attr = this.params.get(oldName);
		if (attr == null) {
			return;
		}
		Attribute nattr = new Attribute(newName);
		nattr.setValues(attr.getValues());
		this.params.remove(oldName);
		this.params.put(newName, nattr);
		
		for (int i=0;i<this.paramNames.size();i++) {
			if (this.paramNames.get(i).equals(oldName)) {
				this.paramNames.set(i, newName);
				break;
			}
		}
	}



	@Override
	public List<NVP> getQueryStringParams() {
		return ((ProxyRequest) this.request).getQueryStringParams();
	}



	@Override
	public List<String> getFormParams() {
		ProxyRequest pr = (ProxyRequest) this.request;
		ArrayList<String> names = new ArrayList<String>();
		names.addAll(pr.getFormParams());
		return names;
	}



	@Override
	public List<String> getFormParamVals(String name) {
		ProxyRequest pr = (ProxyRequest) this.request;
		return pr.getFormParam(name);
	}

}
