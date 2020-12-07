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


package com.tremolosecurity.unison.filter;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStreamReader;
import java.net.URL;

import javax.crypto.SecretKey;
import javax.servlet.http.HttpSession;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.joda.time.DateTime;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.ApplicationType;
import com.tremolosecurity.config.xml.FilterConfigType;
import com.tremolosecurity.config.xml.ParamType;
import com.tremolosecurity.config.xml.ParamWithValueType;
import com.tremolosecurity.config.xml.UrlType;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;

public class CatchFirstLogin implements HttpFilter {

	String touchURL;
	
	String keyAlias;
	String headerName;
	int skew;
	
	String redirectURI;

	String key;
	
	private ConfigManager cfg;
	
	
	
	@Override
	public void doFilter(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		HttpSession session = request.getSession();
		if (session.getAttribute(key) == null) {
			
			AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
			
			Attribute attr = userData.getAttribs().get("userPrincipalName");
			if (attr == null) {
				throw new Exception("User has not userPrincipalName attribute");
			}
			
			DateTime now = new DateTime();
			DateTime future = now.plusMillis(this.skew);
			now = now.minusMillis(skew);
			com.tremolosecurity.lastmile.LastMile lastmile = new com.tremolosecurity.lastmile.LastMile("/Pages/Default.aspx",now,future,0,"chainName");
			lastmile.getAttributes().add(new Attribute("userPrincipalName",attr.getValues().get(0)));
			
			SecretKey sk = this.cfg.getSecretKey(this.keyAlias);
			
			
			
			DefaultHttpClient http = new DefaultHttpClient();
			HttpGet get = new HttpGet(this.touchURL);
			get.addHeader(this.headerName, lastmile.generateLastMileToken(sk));
			HttpResponse resp = http.execute(get);
			
			BufferedReader in = new BufferedReader(new InputStreamReader(resp.getEntity().getContent()));
			
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			String line = null;
			while ((line = in.readLine()) != null) {
				baos.write(line.getBytes("UTF-8"));
				baos.write('\n');
			}
			
			in.close();
			
			String txt = new String(baos.toByteArray());
			
			if (txt.contains("An unexpected error has occured")) {
				response.sendRedirect(this.redirectURI);
				chain.setLogout(true);
				chain.setNoProxy(true);
				return;
			}
			
			session.setAttribute(key, key);
		}
		
		chain.nextFilter(request, response, chain);

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
		Attribute attr = config.getAttribute("touchURL");
		if (attr == null) {
			throw new Exception("touchURL not specified");
		}
		
		this.touchURL = attr.getValues().get(0);
		
		attr = config.getAttribute("redirectURI");
		if (attr == null) {
			throw new Exception("redirectURI not specified");
		}
		this.redirectURI = attr.getValues().get(0);
		
		
		this.cfg = config.getConfigManager();
		
		FilterConfigType filter = this.findLastMile();
		
		if (filter == null) {
			throw new Exception("No last mile configuration for '" + this.touchURL + "'");
		}
		
		for (ParamWithValueType pt : filter.getParam()) {
			if (pt.getName().equalsIgnoreCase("encKeyAlias")) {
				this.keyAlias = pt.getValue();
			} else if (pt.getName().equalsIgnoreCase("headerName")) {
				this.headerName = pt.getValue();
			} else if (pt.getName().equalsIgnoreCase("timeScew")) {
				this.skew = Integer.parseInt(pt.getValue());
			} 
		}
		
		this.key = "SP_VERIFY_ADD_" + this.touchURL;

	}

	private FilterConfigType findLastMile() throws Exception {
		URL url = new URL(this.touchURL);
		
		UrlType cur = null;
		
		for (ApplicationType at : this.cfg.getCfg().getApplications().getApplication()) {
			for (UrlType urlt : at.getUrls().getUrl()) {
				for (String host : urlt.getHost()) {
					if (url.getHost().equalsIgnoreCase(host)) {
						if (url.getPath().startsWith(urlt.getUri())) {
							if (cur == null) {
								cur = urlt;
							} else {
								if (cur.getUri().length() < urlt.getUri().length()) {
									cur = urlt;
								}
							}
						}
					}
				}
			}
		}
		
		if (cur == null) {
			return null;
		}
		
		for (FilterConfigType fct : cur.getFilterChain().getFilter()) {
			if (fct.getClazz().equalsIgnoreCase("com.tremolosecurity.proxy.filters.LastMile")) {
				return fct;
			}
		}
		
		return null;
	}

}
