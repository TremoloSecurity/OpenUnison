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


package com.tremolosecurity.proxy.util;

import java.math.BigInteger;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Iterator;

import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;

import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.CookieConfigType;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.myvd.MyVDConnection;
import com.tremolosecurity.saml.Attribute;

public class ProxyTools {
	static Logger logger = Logger.getLogger(ProxyTools.class);
	
	static ProxyTools instance;
	BigInteger negone;
	
	public ProxyTools() {
		this.negone = BigInteger.valueOf(-1);
	}
	
	public static ProxyTools getInstance() {
		if (instance == null) {
			instance = new ProxyTools();
		}
		
		return instance;
	}
	
	public String getCookieDomain(CookieConfigType cfg,HttpServletRequest request) {
		
		
		//no cookie config, assume host cookie
		if (cfg == null) {
			return null;//request.getServerName();
		}
		
		//if (cfg.getScope().equals(negone)) {
			
			if (cfg.getDomain().equalsIgnoreCase("*") || cfg.getDomain().equalsIgnoreCase(request.getServerName())) {
				return null;//request.getServerName();
			} else {
				return cfg.getDomain();
			}
		//}
		
		//TODO add cookie scope work
		
		//return "";
	}
	
	public String getFqdnUrl(String url,HttpServletRequest req) {
		if (url.startsWith("http")) {
			
		} else {
			StringBuffer sb = new StringBuffer();
			String fwdProto = req.getHeader("X-Forwarded-Proto");
			
			if (req.isSecure() || (fwdProto != null && fwdProto.startsWith("https"))) {
				sb.append("https://");
			} else {
				sb.append("http://");
			}
			
			sb.append(req.getServerName());
			
			if (req.getServerPort() != 80 && req.getServerPort() != 443) {
				sb.append(':').append(req.getServerPort());
			}
			
			sb.append(url);
			url = sb.toString();
		}
		
		return url;
	}
	
	public StringBuffer getGETUrl(HttpFilterRequest req, UrlHolder holder,
			HashMap<String, String> uriParams) {
		StringBuffer proxyToURL = new StringBuffer();
		
		proxyToURL.append(holder.getProxyURL(uriParams));
		
		return proxyToURL;
	}
}
