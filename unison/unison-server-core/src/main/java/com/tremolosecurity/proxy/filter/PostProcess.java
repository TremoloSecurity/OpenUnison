/*
Copyright 2015, 2017 Tremolo Security, Inc.

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
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringBufferInputStream;
import java.math.BigInteger;
import java.net.HttpCookie;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;


import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.config.SocketConfig;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.params.ConnManagerParams;
import org.apache.http.conn.params.ConnPerRouteBean;
import org.apache.http.conn.routing.HttpRoute;
import org.apache.http.conn.scheme.PlainSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager;
import org.apache.http.message.BasicHeader;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpParams;
import org.apache.logging.log4j.Logger;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UnisonConfigManagerImpl;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.proxy.ProxySys;
import com.tremolosecurity.proxy.SessionManager;
import com.tremolosecurity.proxy.SessionManagerImpl;
import com.tremolosecurity.proxy.TremoloHttpSession;
import com.tremolosecurity.proxy.auth.AzSys;
import com.tremolosecurity.proxy.logout.LogoutUtil;
import com.tremolosecurity.proxy.ssl.TremoloTrustManager;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;


public abstract class PostProcess {
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(PostProcess.class);
	
	
	
	public abstract void postProcess(HttpFilterRequest req,
			HttpFilterResponse resp,UrlHolder holder, HttpFilterChain httpFilterChain) throws Exception;
	
	
	
	
	public abstract boolean addHeader(String name);
	
	protected void postProcess(HttpFilterRequest req, HttpFilterResponse resp,
			UrlHolder holder, HttpResponse response,String finalURL,HttpFilterChain curChain,HttpRequestBase httpRequest) throws IOException,
			Exception {
		boolean isText;
		HttpEntity entity = null;
		
		
		
		try {
			entity = response.getEntity();
			/*if (entity != null) {
			    entity = new BufferedHttpEntity(entity);
			}*/
		} catch (Throwable t) {
			throw new Exception(t);
		}
		
		InputStream ins = null;
		boolean entExists = false;
		
		if (entity == null) {
			resp.setStatus(response.getStatusLine().getStatusCode(),response.getStatusLine().getReasonPhrase());
			ins = new StringBufferInputStream("");
		} else {
			try {
				ins = entity.getContent();
				resp.setStatus(response.getStatusLine().getStatusCode(),response.getStatusLine().getReasonPhrase());
				entExists = true;
			} catch (IllegalStateException e) {
				//do nothing
			}
		}
		
		
		
		
		
		
		
		if (entExists) {
			org.apache.http.Header hdr = response.getFirstHeader("Content-Type");
			org.apache.http.Header encoding = response.getFirstHeader("Content-Encoding");
			
			
			
			/*if (hdr == null) {
				isText = false;
			} else {
				isText = response.getFirstHeader("Content-Type").getValue().startsWith("text");
				
				if (encoding != null ) {
					isText = (! encoding.getValue().startsWith("gzip")) && (! encoding.getValue().startsWith("deflate"));
				}
				
				if (isText) {
					resp.setContentType(response.getFirstHeader("Content-Type").getValue());
					resp.setLocale(response.getLocale());
				}
			}*/
			isText = false;
			
			
			
			try {
				resp.setCharacterEncoding(null);
			} catch (Throwable t) {
				//we're not doing anything
			}
			
		
		StringBuffer stmp = new StringBuffer();
		if (response.getFirstHeader("Content-Type") != null) {
			resp.setContentType(response.getFirstHeader("Content-Type").getValue());
		}
		
		if (response.getLocale() != null) {
			resp.setLocale(response.getLocale());
		}
		
		org.apache.http.Header[] headers = response.getAllHeaders();
		for (int i=0;i<headers.length;i++) {
			org.apache.http.Header header = headers[i];
			if (header.getName().equals("Content-Type")) {
				
				continue;
			} else if (header.getName().equals("Content-Type")) {
				
				continue;
			} else if (header.getName().equals("Content-Length")) {
				if (! header.getValue().equals("0")) {
					continue;
				}
			} else if (header.getName().equals("Transfer-Encoding")) {
				continue;
			} else if (header.getName().equalsIgnoreCase("set-cookie") || header.getName().equalsIgnoreCase("set-cookie2")) {
				//System.out.println(header.getValue());
				String cookieVal = header.getValue();
				/*if (cookieVal.endsWith("HttpOnly")) {
					cookieVal = cookieVal.substring(0,cookieVal.indexOf("HttpOnly"));
				}
				
				//System.out.println(cookieVal);*/
				
				List<HttpCookie> cookies = HttpCookie.parse(cookieVal);
				Iterator<HttpCookie> it = cookies.iterator();
				while (it.hasNext()) {
					HttpCookie cookie = it.next();
					String cookieFinalName = cookie.getName();
					if (cookieFinalName.equalsIgnoreCase("JSESSIONID")) {
						stmp.setLength(0);
						stmp.append("JSESSIONID").append('-').append(holder.getApp().getName().replaceAll(" ", "|"));
						cookieFinalName = stmp.toString();
					}
					Cookie respcookie = new Cookie(cookieFinalName, cookie.getValue());
					respcookie.setComment(cookie.getComment());
					if (cookie.getDomain() != null) {
						respcookie.setDomain(cookie.getDomain());
					}
					
					if (cookie.hasExpired()) {
						respcookie.setMaxAge(0);
					} else {
						respcookie.setMaxAge((int) cookie.getMaxAge());
					}
					respcookie.setPath(cookie.getPath());
					
					respcookie.setSecure(cookie.getSecure());
					respcookie.setVersion(cookie.getVersion());
					resp.addCookie(respcookie);
				}
			} else if (header.getName().equals("Location")) {
				
				if (holder.isOverrideHost()) {
					fixRedirect(req, resp, finalURL, header);
				} else {
					resp.addHeader("Location", header.getValue());
				}
			} else {
				resp.addHeader(header.getName(), header.getValue());
			}
			
			
		}
			
		curChain.setIns(ins);
		curChain.setText(isText);
		curChain.setEntity(entity);
		curChain.setHttpRequestBase(httpRequest);
		
		//procData(req, resp, holder, isText, entity, ins);
			
			
			
			
		
		} else {
			isText = false;
		}
	}




	private void fixRedirect(HttpFilterRequest req, HttpFilterResponse resp,
			String finalURL, org.apache.http.Header header) {
		String location = header.getValue();
		if (logger.isDebugEnabled()) {
			logger.debug("Current Location : '" + location + "'");
		}
		
		
		
		if (location.startsWith("/")) {
			
			StringBuffer b = new StringBuffer();
			b.append((req.isSecure() ? "https" : "http")).append("://").append(req.getServerName());
			if (! (req.getServerPort() == 80 || req.getServerPort() == 443)) {
				b.append(':').append(req.getServerPort());
			}
			b.append(location);
			
			
			
			
			location = b.toString(); 
			if (logger.isDebugEnabled()) {
				logger.debug("New Location : '" + location + "'");
			}
			
			
			resp.addHeader("Location", location);
		} else {
			try {
				URL url = new URL(location);
				URL target = new URL(finalURL);
				
				if (! (url.getProtocol().equalsIgnoreCase(target.getProtocol()) && url.getHost().equalsIgnoreCase(target.getHost()) && (url.getPort() == target.getPort())) ) {
					resp.addHeader("Location", location);
				} else {
					
					StringBuffer b = new StringBuffer();
					b.append((req.isSecure() ? "https" : "http")).append("://").append(req.getServerName());
					if (! (req.getServerPort() == 80 || req.getServerPort() == 443)) {
						b.append(':').append(req.getServerPort());
					}
					b.append(url.getPath());
					
					if (url.getQuery() != null) {
						b.append('?').append(url.getQuery());
					}
					
					location = b.toString();
					if (logger.isDebugEnabled()) {
						logger.debug("New Location : '" + location + "'");
					}
					resp.addHeader("Location", location);
				}
			} catch (MalformedURLException e) {
				//not a url, so let the browser worry about it
				resp.addHeader("Location", location);
			}
			
		}
	}




	
	
	protected void setHeadersCookies(HttpFilterRequest req, UrlHolder holder,
			HttpRequestBase method,String finalURL) throws Exception {
		Iterator<String> names;
		names = req.getHeaderNames();
		String cookieName = null;
		URL url = new URL(finalURL);
		
		while (names.hasNext()) {
			String name = names.next();
			if (name.equalsIgnoreCase("Cookie")) {
				cookieName = name;
				continue;
			}
			
			if (logger.isDebugEnabled()) {
				logger.debug("Header : " + name);
			}
			
			
			Attribute attrib = req.getHeader(name);
			Iterator<String> attrVals = attrib.getValues().iterator();
			while (attrVals.hasNext()) {
				String val = attrVals.next();
				
				if (name.equalsIgnoreCase("Content-Type")) {
					continue;
				} else if (name.equalsIgnoreCase("If-Range")) {
					continue;
				} else if (name.equalsIgnoreCase("Range")) {
					continue;
				} else if (name.equalsIgnoreCase("If-None-Match")) {
					continue;
				}
				
				if (name.equalsIgnoreCase("HOST")) {
					
					if (holder.isOverrideHost()) {
						if (logger.isDebugEnabled()) {
							logger.debug("Final URL : '" + finalURL + "'");
						}
						
						val = url.getHost();
						if (url.getPort() != -1) {
							StringBuffer b = new StringBuffer();
							b.append(val).append(":").append(url.getPort());
							val = b.toString();
						}
					} 
				} else  if (name.equalsIgnoreCase("Referer")) {
					
					if (holder.isOverrideReferer()) {
						URL origRef = new URL(val);
						StringBuffer newRef = new StringBuffer();
						
						newRef.append(url.getProtocol()).append("://").append(url.getHost());
						
						if (url.getPort() != -1) {
							newRef.append(':').append(url.getPort());
						}
						
						newRef.append(origRef.getPath());
						
						if (origRef.getQuery() != null) {
							newRef.append('?').append(origRef.getQuery());
						}
						
						if (logger.isDebugEnabled()) {
							logger.debug("Final Ref : '" + newRef.toString() + "'");
						}
					
						val = newRef.toString();
						
					}
					
				} 
				
				if (this.addHeader(name)) {
					if (logger.isDebugEnabled()) {
						logger.debug("Header Added - '" + name + "'='" + val + "'");
					}
					method.addHeader(new BasicHeader(attrib.getName(),val));
				}
			}
		}
		
		
		HashMap<String,Attribute> fromResults = (HashMap<String,Attribute>) req.getAttribute(AzSys.AUTO_IDM_HTTP_HEADERS);
		if (fromResults != null) {
			names = fromResults.keySet().iterator();
			
			while (names.hasNext()) {
				String name = names.next();
				method.removeHeaders(name);
				
				Attribute attrib = fromResults.get(name);
				Iterator<String> attrVals = attrib.getValues().iterator();
				while (attrVals.hasNext()) {
					String val = attrVals.next();
					if (logger.isDebugEnabled()) {
						logger.debug("Header Added - '" + name + "'='" + val + "'");
					}
					method.addHeader(new BasicHeader(name,val));
				}
			}
		}
		
		String sessionCookieName = "";
		
		if (holder.getApp().getCookieConfig() != null) {
			sessionCookieName = holder.getApp().getCookieConfig().getSessionCookieName();
		}
		
		HashSet<String> toRemove = new HashSet<String>();
		toRemove.add(sessionCookieName);
		toRemove.add("autoIdmSessionCookieName");
		toRemove.add("autoIdmAppName");
		toRemove.add("JSESSIONID");
		
		names = req.getCookieNames().iterator();
		StringBuffer cookieHeader = new StringBuffer();
		boolean isFirst = true;
		
		while (names.hasNext()) {
			String name = names.next();
			
			if (toRemove.contains(name)) {
				continue;
			}
			
			ArrayList<Cookie> cookies = req.getCookies(name);
			
			Iterator<Cookie> itc = cookies.iterator();
			while (itc.hasNext()) {
				Cookie cookie = itc.next();
				String cookieFinalName;
				if (cookie.getName().startsWith("JSESSIONID")) {
					String host = cookie.getName().substring(cookie.getName().indexOf('-') + 1);
					host = host.replaceAll("[|]", " ");
					if (!holder.getApp().getName().equalsIgnoreCase(host)) {
						continue;
					}
					
					cookieFinalName = "JSESSIONID";
				} else {
					cookieFinalName = cookie.getName();
				}
				
				String val = cookie.getValue();
				if (logger.isDebugEnabled()) {
					logger.debug("Cookie Added - '" + name + "'='" + val + "'");
				}
				
				cookieHeader.append(cookieFinalName).append('=').append(val).append("; ");
			}
		}
		
		if (cookieHeader.length() > 0) {
			if (cookieName == null) {
				cookieName = "Cookie";
			}
			
			method.addHeader(new BasicHeader(cookieName,cookieHeader.toString()));
		}
	}
	
	public CloseableHttpClient getHttp(String finalURL,HttpServletRequest request,UrlHolder holder) {
		ConfigManager cfgMgr = holder.getConfig();
		HttpSession session = request.getSession();
		PoolingHttpClientConnectionManager phcm = (PoolingHttpClientConnectionManager) session.getAttribute("TREMOLO_HTTP_POOL");
		CloseableHttpClient http = (CloseableHttpClient) session.getAttribute("TREMOLO_HTTP_CLIENT");
		if (http == null) {
			
			if (holder.getApp().getCookieConfig() == null || holder.getApp().getCookieConfig().isCookiesEnabled() == null || holder.getApp().getCookieConfig().isCookiesEnabled()) {
			
				//create a new connection manager and client
				phcm = new PoolingHttpClientConnectionManager(cfgMgr.getHttpClientSocketRegistry());
				BigInteger num = cfgMgr.getCfg().getThreadsPerRoute();
				if (num == null) {
					phcm.setDefaultMaxPerRoute(6);
				} else {
					phcm.setDefaultMaxPerRoute(num.intValue());
				}
				phcm.setDefaultSocketConfig(SocketConfig.custom().setSoKeepAlive(true).build());
				phcm.close();
				http = HttpClients.custom().setConnectionManager(phcm).setDefaultRequestConfig(cfgMgr.getGlobalHttpClientConfig()).build();
				
				session.setAttribute("TREMOLO_HTTP_POOL", phcm);
				session.setAttribute("TREMOLO_HTTP_CLIENT", http);
	
	
	
				LogoutUtil.insertFirstLogoutHandler(request, new CloseHttpConnectionsOnLogout(http,phcm));
			} else {
				//no session, need to create single connection
				
				BasicHttpClientConnectionManager bhcm = new BasicHttpClientConnectionManager(
						cfgMgr.getHttpClientSocketRegistry());

				RequestConfig rc = RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD).setRedirectsEnabled(false)
						.build();

				http = HttpClients.custom()
						                  .setConnectionManager(bhcm)
						                  .setDefaultRequestConfig(rc)
						                  .build();
				
				session.setAttribute("TREMOLO_HTTP_CM", bhcm);
				session.setAttribute("TREMOLO_HTTP_CLIENT", http);
				
				// remove from the session pool
				
				SessionManager sessionMgr = (SessionManager) GlobalEntries.getGlobalEntries().getConfigManager().getContext()
				        .getAttribute(ProxyConstants.TREMOLO_SESSION_MANAGER);
				sessionMgr.removeSessionFromCache((TremoloHttpSession) session);
				
				
			}
			
		}
		
		return http;
	}
}
