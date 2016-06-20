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


package com.tremolosecurity.proxy.filters;

import java.net.CookieManager;
import java.net.HttpCookie;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;

import javax.servlet.http.Cookie;

import org.apache.http.impl.client.BasicCookieStore;
import org.apache.logging.log4j.Logger;


import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.proxy.ProxyResponse;
import com.tremolosecurity.proxy.TremoloHttpSession;
import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.proxy.util.ProxyTools;
import com.tremolosecurity.saml.Attribute;



public class HideCookie implements HttpFilter {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(HideCookie.class);

	private static final String TREMOLO_HIDE_COOKIE_JAR = "TREMOLO_HIDE_COOKIE_JAR";

	@Override
	public void doFilter(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {

		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		String proxyTo = holder.getUrl().getProxyTo();
		
		HashMap<String,String> uriParams = new HashMap<String,String>();
		uriParams.put("fullURI", request.getRequestURI());
		
		Iterator<String> names;
		StringBuffer proxyToURL = ProxyTools.getInstance().getGETUrl(request, holder, uriParams);
		
		
		
		if (! holder.isOverrideHost()) {
			String surl = proxyToURL.toString();
			String proto = surl.substring(0,surl.indexOf("://") + 3);
			String url = surl.substring(surl.indexOf('/', 9));
			proxyToURL.setLength(0);
			proxyToURL.append(proto);
			
			Attribute host = request.getHeader("Host");
			if (host == null) {
				host = request.getHeader("host");
			}
			proxyToURL.append(host.getValues().get(0));
			proxyToURL.append(url);
		}
		
		
		URL url = new URL(proxyToURL.toString());
		
		CookieManager cookieJar = (CookieManager) request.getSession().getAttribute(TREMOLO_HIDE_COOKIE_JAR);
		
		if (cookieJar == null) {
			cookieJar = new CookieManager();
			request.getSession().setAttribute(TREMOLO_HIDE_COOKIE_JAR,
					cookieJar);
		}

		
		
		
		
		
		Map<String,List<String>> cookies = cookieJar.get(url.toURI(), new HashMap<String,List<String>>());
		
		for (String headerName : cookies.keySet()) {
			for (String val : cookies.get(headerName)) {
				if (headerName.equalsIgnoreCase("cookie")) {
					String name = val.substring(0,val.indexOf('='));
					String value = val.substring(val.indexOf('=') + 1);
					request.addCookie(new Cookie(name,value));
				}
				
				
				
				
			}
			
			
		}
		
		
		
		
		

		chain.nextFilter(request, response, chain);

		StringBuffer b = new StringBuffer();
		ArrayList<String> cookieHeaders = new ArrayList<String>();
		
		for (Cookie cookie : response.getCookies()) {
			HttpCookie httpCookie = new HttpCookie(cookie.getName(), cookie.getValue());
			
			if (cookie.getSecure()) {
				httpCookie.setSecure(true);
			}
			
			if (cookie.getComment() != null) {
				httpCookie.setComment(cookie.getComment());
			}
			
			if (cookie.getMaxAge() >= 0) {
				httpCookie.setMaxAge(cookie.getMaxAge());
			}
			
			if (cookie.getPath() != null) {
				httpCookie.setPath(cookie.getPath());
			}
			
			httpCookie.setVersion(cookie.getVersion());
			
			cookieHeaders.add(httpCookie.toString());
			
		}
		
		Map<String,List<String>> respHeaders = new HashMap<String,List<String>>();
		respHeaders.put("Set-Cookie", cookieHeaders);
		
		cookieJar.put(url.toURI(),respHeaders);
		
		response.getCookies().clear();

	}

	@Override
	public void filterResponseText(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain,
			StringBuffer data) throws Exception {

		chain.nextFilterResponseText(request, response, chain, data);

	}

	@Override
	public void filterResponseBinary(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain, byte[] data,
			int length) throws Exception {
		chain.nextFilterResponseBinary(request, response, chain, data, length);

	}

	@Override
	public void initFilter(HttpFilterConfig config) throws Exception {
		// TODO Auto-generated method stub

	}

}