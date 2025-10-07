/*
Copyright 2015, 2018 Tremolo Security, Inc.

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
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Supplier;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;

import org.apache.logging.log4j.Logger;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormat;

import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.ApplicationType;
import com.tremolosecurity.proxy.cookies.UnisonCookie;
import com.tremolosecurity.proxy.util.ProxyTools;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.util.NVP;

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
		StringBuilder cookieVal = new StringBuilder();
		
		org.joda.time.format.DateTimeFormatter expiresFormat = DateTimeFormat.forPattern( "EEE, dd-MMM-yyyy HH:mm:ss 'GMT'" ).withLocale(Locale.US);
		

		if ((holder == null || holder.getApp() == null || holder.getApp().getCookieConfig() == null || holder.getApp().getCookieConfig() == null || holder.getApp().getCookieConfig().isCookiesEnabled() == null)  || holder.getApp().getCookieConfig().isCookiesEnabled()) {
			
			for (Cookie cookie : this.cookies) {
					if (holder != null) {
						addCookieToResponse(holder.getApp(), cookieVal, expiresFormat, cookie,this.resp);
					}
					
					//this.resp.addCookie(cookie);
					
				
			}
		}

		
		
		int status = ((HttpServletResponse) this.getResponse()).getStatus();
		String redirectLocation = null;
		if ((status < 200 || status > 299)	 && status != 302 && status != 301) {
			if (holder != null) {
				redirectLocation = holder.getConfig().getErrorPages().get(status);
			}
			
		}
		
		boolean isHtml = redirectLocation != null &&  req.getAttribute("com.tremolosecurity.unison.proxy.noRedirectOnError") == null;


		List<NVP> localHeaders = new ArrayList<NVP>();
		for (Attribute attr : this.headers.values()) {
			String val = attr.getValues().get(0);
			if (redirectLocation != null) {
				if (attr.getName().toLowerCase().contains("content-type")) {
					isHtml = val.toLowerCase().contains("html");
				} else if (attr.getName().equalsIgnoreCase("Location")) {
					continue;
				}
			}
			localHeaders.add(new NVP(attr.getName(),val));
		}

		if (isHtml) {
			resp.setStatus(302);
			localHeaders.add(new NVP("Location",redirectLocation));
		}

		for (NVP nvp : localHeaders) {
			this.resp.addHeader(nvp.getName(), nvp.getValue());
		}
		
		this.cookies.clear();
		this.headers.clear();
	}

	public static void addCookieToResponse(ApplicationType appConfig, StringBuilder cookieVal,
			org.joda.time.format.DateTimeFormatter expiresFormat, Cookie cookie,HttpServletResponse resp) {
		
		if (appConfig != null && appConfig.getCookieConfig() != null && appConfig.getCookieConfig().isCookiesEnabled() != null && ! appConfig.getCookieConfig().isCookiesEnabled()) {
			return;
		}
		
		
		
		cookieVal.setLength(0);
		
		String cookieRawVal = ecnodeCookieValue(cookie.getValue());
		
		
		cookieVal.append(cookie.getName()).append('=').append(cookieRawVal).append(';');
		
		
			
		
		
		
		if (appConfig == null) {
			//i don't think this is possible
		} else {
			boolean setDomainInfo = true;
			if (cookie instanceof UnisonCookie) {
				setDomainInfo = ! ((UnisonCookie) cookie).isOverrideValues();
			}

			if (setDomainInfo) {
				String domain = appConfig.getCookieConfig().getDomain();
				if (! domain.equalsIgnoreCase("*")) {
					cookie.setDomain(domain);
				}
				
				if (cookie.getDomain() != null && ! cookie.getDomain().isEmpty()) {
					cookieVal.append(" Domain=").append(cookie.getDomain()).append(';');
				}
				
				
				
				
			}
			
			//cookie.setSecure(holder.getApp().getCookieConfig().isSecure());
			if (appConfig.getCookieConfig().isSecure()) {
				cookieVal.append(" Secure;");
			}
			
			cookie.setHttpOnly(appConfig.getCookieConfig().isHttpOnly() != null && appConfig.getCookieConfig().isHttpOnly());
			if (appConfig.getCookieConfig().isHttpOnly() != null && appConfig.getCookieConfig().isHttpOnly()) {
				cookieVal.append(" HttpOnly;");
			}
			
			if (cookie.getPath() != null && ! cookie.getPath().isEmpty()) {
				cookieVal.append(" Path=").append(cookie.getPath()).append(';');
			}
		}
		
		if (cookie.getMaxAge() != -1) {
			
			DateTime expires = null;
			
			if (cookie.getMaxAge() == 0) {
				expires = new DateTime(cookie.getMaxAge() * 1000,DateTimeZone.UTC);
			} else {
				expires = new DateTime().plusSeconds(cookie.getMaxAge());
			}
			
			
			cookieVal.append(" Max-Age=").append(cookie.getMaxAge()).append("; Expires=").append(expires.toString(expiresFormat)).append(';');
		}
		
		if (appConfig.getCookieConfig().getSameSite() != null && ! appConfig.getCookieConfig().getSameSite().equals("Ignore")) {
			cookieVal.append(" SameSite=").append(appConfig.getCookieConfig().getSameSite()).append(";");
		}


		if (cookie.getAttribute("Partitioned") != null) {
			cookieVal.append(" Partitioned;");
		}
		
		resp.addHeader("Set-Cookie", cookieVal.toString());
	}
	
	private static String ecnodeCookieValue(String value) {
		StringBuilder val = new StringBuilder();
		boolean needsQuotes = false;
		
		char[] chars = value.toCharArray();
		for (char c : chars) {
			if (Character.isWhitespace(c) || c == ';') {
				needsQuotes = true;
				val.append(c);
			} else if (c == '"') {
				needsQuotes = true;
				val.append('\\').append('"');
			} else {
				val.append(c);
			}
		}
		
		if (needsQuotes) {
			val.insert(0, '"').append('"');
		}
		
		return val.toString();
	}

	private static boolean needsEncoding(String cookieRawVal) {
		char[] chars = cookieRawVal.toCharArray();
		for (char c : chars) {
			if (Character.isWhitespace(c) || c == ';') {
				return true;
			}
		}
		
		return false;
	}

	@Override
	public String encodeRedirectURL(String url) {
		return resp.encodeRedirectURL(url);
	}

	
	public String encodeRedirectUrl(String url) {
		return resp.encodeRedirectURL(url);
	}

	@Override
	public String encodeURL(String url) {
		return resp.encodeURL(url);
	}

	
	public String encodeUrl(String url) {
		return resp.encodeURL(url);
	}

	@Override
	public void sendError(int code) throws IOException {
		resp.setStatus(code);

	}

	@Override
	public void sendError(int code, String status) throws IOException {
		resp.sendError(code, status);

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

	
	

	public static void addCookieToResponse(UrlHolder holder, Cookie sessionCookieName, HttpServletResponse resp2) {
		
		if (holder != null) {
			ProxyResponse.addCookieToResponse(holder.getApp(), new StringBuilder(), DateTimeFormat.forPattern( "EEE, dd-MMM-yyyy HH:mm:ss 'GMT'" ).withLocale(Locale.US), sessionCookieName, resp2);
		}
		
	}
	
	public static void addCookieToResponse(ApplicationType appConfig, Cookie sessionCookieName, HttpServletResponse resp2) {
		
		ProxyResponse.addCookieToResponse(appConfig, new StringBuilder(), DateTimeFormat.forPattern( "EEE, dd-MMM-yyyy HH:mm:ss 'GMT'" ).withLocale(Locale.US), sessionCookieName, resp2);	
		
	}

	@Override
	public int getStatus() {
		return resp.getStatus();
	}

	@Override
	public String getHeader(String name) {
		Attribute attr = this.headers.get(name);
		if (attr != null) {
			return attr.getValues().get(0);
		} else {
			return null;
		}
	}

	@Override
	public Collection<String> getHeaders(String name) {
		Attribute attr = this.headers.get(name);
		if (attr != null) {
			return attr.getValues();
		} else {
			return null;
		}
	}

	@Override
	public Collection<String> getHeaderNames() {
		return this.headers.keySet();
	}

	@Override
	public void setTrailerFields(Supplier<Map<String, String>> supplier) {
		
		resp.setTrailerFields(supplier);
	}

	@Override
	public Supplier<Map<String, String>> getTrailerFields() {
		
		return resp.getTrailerFields();
	}
	
	

}
