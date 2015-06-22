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


package com.tremolosecurity.proxy.filter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletInputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.fileupload.FileItem;

import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.util.NVP;

public interface HttpFilterRequest {

	public abstract AuthInfo getAuthInfo();

	public abstract String getContextPath();

	public abstract Set<String> getCookieNames();

	public abstract ArrayList<Cookie> getCookies(String name);

	public abstract void addCookie(Cookie cookie);

	public abstract void removeCookie(String name);

	public abstract Iterator<String> getHeaderNames();

	public abstract Attribute getHeader(String name);

	public abstract void addHeader(Attribute header);

	public abstract void removeHeader(String name);

	public abstract String getMethod();

	public abstract String getPathInfo();

	public abstract String getPathTranslated();

	public abstract String getQueryString();

	public abstract String getRequestURI();

	public abstract StringBuffer getRequestURL();

	public abstract String getRequestedSessionId();

	public abstract String getServletPath();

	public abstract HttpSession getSession();

	public abstract HttpSession getSession(boolean arg0);

	public abstract boolean isRequestedSessionIdFromCookie();

	public abstract boolean isRequestedSessionIdFromURL();

	public abstract boolean isRequestedSessionIdFromUrl();

	public abstract boolean isRequestedSessionIdValid();

	public abstract Object getAttribute(String arg0);

	public abstract Enumeration getAttributeNames();

	public abstract String getCharacterEncoding();

	public abstract int getContentLength();

	public abstract String getContentType();

	public abstract ServletInputStream getInputStream() throws IOException;

	public abstract Locale getLocale();

	public abstract Enumeration getLocales();

	public abstract Iterator<String> getParameterNames();

	public abstract Attribute getParameter(String name);

	public abstract void addParameter(Attribute attrib);

	public abstract void removeParameter(String name);

	public abstract String getProtocol();

	public abstract BufferedReader getReader() throws IOException;

	public abstract String getRealPath(String arg0);

	public abstract String getRemoteAddr();

	public abstract String getRemoteHost();

	public abstract RequestDispatcher getRequestDispatcher(String arg0);

	public abstract String getScheme();

	public abstract String getServerName();

	public abstract int getServerPort();

	public abstract boolean isSecure();

	public abstract void removeAttribute(String arg0);

	public abstract void setAttribute(String arg0, Object arg1);

	public abstract void setCharacterEncoding(String arg0)
			throws UnsupportedEncodingException;

	public abstract boolean isMultiPart();

	public abstract boolean isParamsInBody();

	public abstract HashMap<String, ArrayList<FileItem>> getFiles();

	public abstract HttpServletRequest getServletRequest();

	public abstract void renameAttribute(String oldName, String newName);
	
	public abstract List<NVP> getQueryStringParams();
	
	public abstract List<String> getFormParams();
	
	

	List<String> getFormParamVals(String name);

}