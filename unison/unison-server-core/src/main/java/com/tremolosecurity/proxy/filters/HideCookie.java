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


package com.tremolosecurity.proxy.filters;

import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.ListIterator;

import javax.servlet.http.Cookie;

import org.apache.log4j.Logger;

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



public class HideCookie implements HttpFilter {

	static Logger logger = Logger.getLogger(HideCookie.class);

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
			proxyToURL.append(request.getHeader("Host").getValues().get(0));
			proxyToURL.append(url);
		}
		
		
		URL url = new URL(proxyToURL.toString());
		

		
		HashMap<String, SerialCookie> cookieJar = (HashMap<String, SerialCookie>) request
				.getSession().getAttribute(TREMOLO_HIDE_COOKIE_JAR);
		if (cookieJar == null) {
			cookieJar = new HashMap<String, SerialCookie>();
			request.getSession().setAttribute(TREMOLO_HIDE_COOKIE_JAR,
					cookieJar);
		}

		Iterator<String> itc = cookieJar.keySet().iterator();
		ArrayList<String> toremove = new ArrayList<String>();

		StringBuffer periodDomain = new StringBuffer();
		
		while (itc.hasNext()) {

			String key = itc.next();
			SerialCookie cookie = cookieJar.get(key);
			
			periodDomain.setLength(0);
			periodDomain.append('.').append(url.getHost());
			
			if (logger.isDebugEnabled()) {
				logger.debug("Cookie Domain : '" + cookie.getDomain() + "', URL Host : '" + url.getHost() + "'");
			}
			
			if (cookie.getDomain() == null
					|| url.getHost().endsWith(cookie.getDomain()) || periodDomain.toString().endsWith(cookie.getDomain()) ) {

				
				if (logger.isDebugEnabled()) {
					logger.debug("Cookie Path : '" + cookie.getPath() + "', URL Path : '" + request.getRequestURI() + "'");
				}
				
				if (cookie.getPath() == null
					
						|| request.getRequestURI().startsWith(cookie.getPath())) {

					logger.debug("Cookie Secure : '" + cookie.getSecure() + "', URL secure : '" + request.isSecure() + "'");
					
					if ((!cookie.getSecure())
							|| (cookie.getSecure() && request.isSecure())) {

						logger.debug("Cookie valid : '" + cookie.isValid() + "'");
						
						if (cookie.isValid()) {
							if (logger.isDebugEnabled()) {
								logger.debug("Adding cookie to request : '" + cookie.getName() + "'");
							}
							request.addCookie(cookie.genCookie());

						} else {
							if (logger.isDebugEnabled()) {
								logger.debug("Deleting Cookie : '" + key + "'");
							}
							toremove.add(key);
						}

					}

				}

			}
		}

		itc = toremove.iterator();
		while (itc.hasNext()) {
			cookieJar.remove(itc.next());
		}

		chain.nextFilter(request, response, chain);

		ArrayList<Cookie> cookies = response.getCookies();
		Iterator<Cookie> it = cookies.iterator();

		// logger.info("adding cookies to the jar");

		while (it.hasNext()) {
			Cookie c = it.next();
			if (logger.isDebugEnabled()) {
				logger.debug("Response Cookie : '" + c.getName() + "=" + c.getValue()
						+ "'");
			}
			StringBuffer b = new StringBuffer();
			b.append(c.getName()).append(c.getDomain()).append(c.getPath());
			
			//logger.info("Cookie : '" + b + "'='" + c.getValue() + "' - max age : '" + c.getMaxAge() + "'");
			
			if (c.getMaxAge() == 0) {
				if (logger.isDebugEnabled()) {
					logger.debug("Removing response cookie : '" + c.getName() + "'");
				}
				cookieJar.remove(b.toString());
			} else {
				logger.debug("Adding response cookie : '" + c.getName() + "'");
				cookieJar.put(b.toString(), new SerialCookie(c));
			}
			
			
		}
		cookies.clear();

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