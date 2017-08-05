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


package com.tremolosecurity.proxy;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Locale;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.proxy.util.ProxyTools;
import com.tremolosecurity.saml.Attribute;

public class ProxyResponse extends HttpServletResponseWrapper {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(ProxyResponse.class);
	
	HttpServletResponse resp;
	HttpServletRequest req;
	
	ArrayList<Cookie> cookies;
	HashMap<String,Attribute> headers;

	boolean headersAndCookiesPushed;
	
	public ProxyResponse(HttpServletResponse resp,HttpServletRequest req) {
		super(resp);
		this.cookies = new ArrayList<Cookie>();
		this.headers = new HashMap<String,Attribute>();
		
		
		this.resp = resp;
		this.req = req;
		
		headersAndCookiesPushed = false;
	}
	
	@Override
	public void flushBuffer() throws IOException {
		resp.flushBuffer();

	}

	@Override
	public int getBufferSize() {
		return resp.getBufferSize();
	}

	@Override
	public String getCharacterEncoding() {
		return resp.getCharacterEncoding();
	}

	@Override
	public String getContentType() {
		return resp.getContentType();
	}

	@Override
	public Locale getLocale() {
		return resp.getLocale();
	}

	@Override
	public ServletOutputStream getOutputStream() throws IOException {
		return resp.getOutputStream();
	}

	@Override
	public PrintWriter getWriter() throws IOException {
		return resp.getWriter();
	}

	@Override
	public boolean isCommitted() {
		return resp.isCommitted();
	}

	@Override
	public void reset() {
		resp.reset();

	}

	@Override
	public void resetBuffer() {
		resp.resetBuffer();

	}

	@Override
	public void setBufferSize(int size) {
		resp.setBufferSize(size);

	}

	@Override
	public void setCharacterEncoding(String encoding) {
		resp.setCharacterEncoding(encoding);

	}

	@Override
	public void setContentLength(int size) {
		resp.setContentLength(size);

	}

	@Override
	public void setContentType(String contentType) {
		resp.setContentType(contentType);

	}

	@Override
	public void setLocale(Locale locale) {
		resp.setLocale(locale);

	}

	@Override
	public void addCookie(Cookie cookie) {
		this.cookies.add(cookie);
		
	}
	
	public ArrayList<Cookie> getCookies() {
		return this.cookies;
	}

	@Override
	public void addDateHeader(String name, long val) {
		Attribute attr = this.headers.get(name);
		if (attr == null) {
			attr = new Attribute(name);
			this.headers.put(name, attr);
		}
		
		attr.getValues().add(Long.toString(val));

	}

	@Override
	public void addHeader(String name, String val) {
		Attribute attr = this.headers.get(name);
		if (attr == null) {
			attr = new Attribute(name);
			this.headers.put(name, attr);
		}
		
		attr.getValues().add(val);

	}

	@Override
	public void addIntHeader(String name, int val) {
		Attribute attr = this.headers.get(name);
		if (attr == null) {
			attr = new Attribute(name);
			this.headers.put(name, attr);
		}
		
		attr.getValues().add(Long.toString(val));

	}

	@Override
	public boolean containsHeader(String name) {
		return this.headers.containsKey(name);
	}
	
	public Attribute getUnisonHeader(String name) {
		return this.headers.get(name);
	}
	
	public void removeHeader(String name) {
		this.headers.remove(name);
	}

	public void pushHeadersAndCookies(UrlHolder holder) {
		
		if (headersAndCookiesPushed) {
			return;
		}
		
		headersAndCookiesPushed = true;
		
		for (Cookie cookie : this.cookies) {
			
				if (holder == null || holder.getApp().getCookieConfig() == null) {
					//i don't think this is possible
				} else {
					String domain = holder.getApp().getCookieConfig().getDomain();
					if (! domain.equalsIgnoreCase("*")) {
						cookie.setDomain(domain);
					}
					
					cookie.setSecure(holder.getApp().getCookieConfig().isSecure());
					cookie.setHttpOnly(holder.getApp().getCookieConfig().isHttpOnly() != null && holder.getApp().getCookieConfig().isHttpOnly());
				}
				
				
				
				this.resp.addCookie(cookie);
				
			
		}
		
		Iterator<Attribute> itAttr = this.headers.values().iterator();
		while (itAttr.hasNext()) {
			Attribute attr = itAttr.next();
			Iterator<String> vals = attr.getValues().iterator();
			this.resp.addHeader(attr.getName(), vals.next());
		}
		
		this.cookies.clear();
		this.headers.clear();
	}
	
	@Override
	public String encodeRedirectURL(String url) {
		return resp.encodeRedirectURL(url);
	}

	@Override
	public String encodeRedirectUrl(String url) {
		return resp.encodeRedirectURL(url);
	}

	@Override
	public String encodeURL(String url) {
		return resp.encodeURL(url);
	}

	@Override
	public String encodeUrl(String url) {
		return resp.encodeUrl(url);
	}

	@Override
	public void sendError(int code) throws IOException {
		resp.setStatus(code);

	}

	@Override
	public void sendError(int code, String status) throws IOException {
		resp.setStatus(code, status);

	}

	@Override
	public void sendRedirect(String url) throws IOException {
		resp.setStatus(302);
		
		url = ProxyTools.getInstance().getFqdnUrl(url, req);
		this.removeHeader("Location");
		this.addHeader("Location", url);

	}

	@Override
	public void setDateHeader(String name, long val) {
		resp.setDateHeader(name, val);

	}

	@Override
	public void setHeader(String name, String val) {
		resp.setHeader(name, val);

	}

	@Override
	public void setIntHeader(String name, int val) {
		resp.setIntHeader(name, val);

	}

	@Override
	public void setStatus(int status) {
		resp.setStatus(status);

	}

	@Override
	public void setStatus(int status, String line) {
		resp.setStatus(status, line);

	}

}
