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

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Locale;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.proxy.ProxyResponse;
import com.tremolosecurity.proxy.TremoloHttpSession;
import com.tremolosecurity.saml.Attribute;

public class HttpFilterResponseImpl implements HttpFilterResponse {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(HttpFilterResponseImpl.class);
	
	ProxyResponse response;
	
	public HttpFilterResponseImpl(HttpServletResponse response) {
		this.response = (ProxyResponse) response;
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterResponse#addCookie(javax.servlet.http.Cookie)
	 */
	@Override
	public void addCookie(Cookie arg0) {
		this.response.addCookie(arg0);

	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterResponse#getCookies()
	 */
	@Override
	public ArrayList<Cookie> getCookies() {
		return this.response.getCookies();
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterResponse#removeHeader(java.lang.String)
	 */
	@Override
	public void removeHeader(String name) {
		this.response.removeHeader(name);
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterResponse#getHeader(java.lang.String)
	 */
	@Override
	public Attribute getHeader(String name) {
		return this.response.getUnisonHeader(name);
	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterResponse#addDateHeader(java.lang.String, long)
	 */
	@Override
	public void addDateHeader(String arg0, long arg1) {
		response.addDateHeader(arg0, arg1);

	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterResponse#addHeader(java.lang.String, java.lang.String)
	 */
	@Override
	public void addHeader(String arg0, String arg1) {
		response.addHeader(arg0, arg1);

	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterResponse#addIntHeader(java.lang.String, int)
	 */
	@Override
	public void addIntHeader(String arg0, int arg1) {
		response.addIntHeader(arg0, arg1);

	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterResponse#containsHeader(java.lang.String)
	 */
	@Override
	public boolean containsHeader(String arg0) {
		return this.response.containsHeader(arg0);
		
	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterResponse#encodeRedirectURL(java.lang.String)
	 */
	@Override
	public String encodeRedirectURL(String arg0) {
		return this.response.encodeRedirectURL(arg0);
	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterResponse#encodeRedirectUrl(java.lang.String)
	 */
	@Override
	public String encodeRedirectUrl(String arg0) {
		return this.encodeRedirectUrl(arg0);

	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterResponse#encodeURL(java.lang.String)
	 */
	@Override
	public String encodeURL(String arg0) {
		return this.response.encodeUrl(arg0);
		
	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterResponse#encodeUrl(java.lang.String)
	 */
	@Override
	public String encodeUrl(String arg0) {
		return this.response.encodeUrl(arg0);
	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterResponse#sendError(int)
	 */
	@Override
	public void sendError(int arg0) throws IOException {
		this.response.sendError(arg0);

	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterResponse#sendError(int, java.lang.String)
	 */
	@Override
	public void sendError(int arg0, String arg1) throws IOException {
		this.response.sendError(arg0, arg1);

	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterResponse#sendRedirect(java.lang.String)
	 */
	@Override
	public void sendRedirect(String arg0) throws IOException {
		this.response.sendRedirect(arg0);
	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterResponse#setDateHeader(java.lang.String, long)
	 */
	@Override
	public void setDateHeader(String arg0, long arg1) {
		this.response.setDateHeader(arg0, arg1);

	}


	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterResponse#setHeader(java.lang.String, java.lang.String)
	 */
	@Override
	public void setHeader(String arg0, String arg1) {
		this.response.setHeader(arg0, arg1);

	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterResponse#setIntHeader(java.lang.String, int)
	 */
	@Override
	public void setIntHeader(String arg0, int arg1) {
		this.response.setIntHeader(arg0, arg1);

	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterResponse#setStatus(int)
	 */
	@Override
	public void setStatus(int arg0) {
		this.response.setStatus(arg0);

	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterResponse#setStatus(int, java.lang.String)
	 */
	@Override
	public void setStatus(int arg0, String arg1) {
		this.response.setStatus(arg0, arg1);

	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterResponse#getServletResponse()
	 */
	@Override
	public HttpServletResponse getServletResponse() {
		return this.response;
	}

	


	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterResponse#getCharacterEncoding()
	 */
	@Override
	public String getCharacterEncoding() {
		return this.response.getCharacterEncoding();
	}


	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterResponse#getLocale()
	 */
	@Override
	public Locale getLocale() {
		return this.response.getLocale();
	}

	

	

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterResponse#isCommitted()
	 */
	@Override
	public boolean isCommitted() {
		return this.response.isCommitted();
	}

	

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterResponse#setContentType(java.lang.String)
	 */
	@Override
	public void setContentType(String arg0) {
		this.response.setContentType(arg0);

	}

	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterResponse#setLocale(java.util.Locale)
	 */
	@Override
	public void setLocale(Locale arg0) {
		this.response.setLocale(arg0);

	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterResponse#getWriter()
	 */
	@Override
	public PrintWriter getWriter() throws IOException {
		return response.getWriter();
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterResponse#getOutputStream()
	 */
	@Override
	public OutputStream getOutputStream() throws IOException {
		return response.getOutputStream();
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterResponse#setCharacterEncoding(java.lang.String)
	 */
	@Override
	public void setCharacterEncoding(String encType) {
		response.setCharacterEncoding(encType);
	}

}
