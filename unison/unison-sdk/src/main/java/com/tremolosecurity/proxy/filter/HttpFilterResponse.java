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

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Locale;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;

import com.tremolosecurity.saml.Attribute;

public interface HttpFilterResponse {

	public abstract void addCookie(Cookie arg0);

	public abstract ArrayList<Cookie> getCookies();

	public abstract void removeHeader(String name);

	public abstract Attribute getHeader(String name);

	public abstract void addDateHeader(String arg0, long arg1);

	public abstract void addHeader(String arg0, String arg1);

	public abstract void addIntHeader(String arg0, int arg1);

	public abstract boolean containsHeader(String arg0);

	public abstract String encodeRedirectURL(String arg0);

	public abstract String encodeRedirectUrl(String arg0);

	public abstract String encodeURL(String arg0);

	public abstract String encodeUrl(String arg0);

	public abstract void sendError(int arg0) throws IOException;

	public abstract void sendError(int arg0, String arg1) throws IOException;

	public abstract void sendRedirect(String arg0) throws IOException;

	public abstract void setDateHeader(String arg0, long arg1);

	public abstract void setHeader(String arg0, String arg1);

	public abstract void setIntHeader(String arg0, int arg1);

	public abstract void setStatus(int arg0);

	public abstract void setStatus(int arg0, String arg1);

	public abstract HttpServletResponse getServletResponse();

	public abstract String getCharacterEncoding();

	public abstract Locale getLocale();

	public abstract boolean isCommitted();

	public abstract void setContentType(String arg0);

	public abstract void setLocale(Locale arg0);

	public abstract PrintWriter getWriter() throws IOException;

	public abstract OutputStream getOutputStream() throws IOException;

	public abstract void setCharacterEncoding(String encType);

}