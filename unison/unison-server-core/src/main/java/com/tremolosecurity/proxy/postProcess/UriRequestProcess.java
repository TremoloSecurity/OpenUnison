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


package com.tremolosecurity.proxy.postProcess;

import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.tremolosecurity.proxy.HttpUpgradeRequestManager;
import com.tremolosecurity.proxy.ProxyResponse;
import com.tremolosecurity.proxy.ProxySys;
import org.apache.http.HttpResponse;
import org.apache.http.ProtocolException;
import org.apache.http.client.CookieStore;
import org.apache.http.client.HttpClient;
import org.apache.http.client.RedirectHandler;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.params.ClientPNames;
import org.apache.http.client.params.CookiePolicy;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.cookie.Cookie;
import org.apache.http.cookie.CookieOrigin;
import org.apache.http.cookie.CookieSpec;
import org.apache.http.cookie.CookieSpecFactory;
import org.apache.http.cookie.MalformedCookieException;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.cookie.BrowserCompatSpec;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.HttpContext;
import org.apache.logging.log4j.Logger;

import com.tremolosecurity.config.util.UnisonConfigManagerImpl;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.filter.PostProcess;
import com.tremolosecurity.proxy.http.UriMethod;
import com.tremolosecurity.proxy.myvd.MyVDConnection;
import com.tremolosecurity.proxy.ssl.TremoloSSLSocketFactory;
import com.tremolosecurity.proxy.ssl.TremoloTrustManager;
import com.tremolosecurity.proxy.util.ProxyTools;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.util.NVP;

public class UriRequestProcess extends PostProcess {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(UriRequestProcess.class);
	
	@Override
	public void postProcess(HttpFilterRequest req, HttpFilterResponse resp,
			UrlHolder holder,HttpFilterChain chain) throws Exception {
		
		
		String proxyTo = holder.getUrl().getProxyTo();
		
		HashMap<String,String> uriParams = (HashMap<String,String>) req.getAttribute("TREMOLO_URI_PARAMS");
		
		Iterator<String> names;
		StringBuffer proxyToURL = ProxyTools.getInstance().getGETUrl(req, holder, uriParams);
		
		boolean first = true;
		for (NVP p : req.getQueryStringParams()) {
			if (first) {
				proxyToURL.append('?');
				first = false;
			} else {
				proxyToURL.append('&');
			}
			
			proxyToURL.append(p.getName()).append('=').append(URLEncoder.encode(p.getValue(),"UTF-8"));
		}
		
		
		
		
		
		com.tremolosecurity.proxy.HttpUpgradeRequestManager upgradeRequestManager = GlobalEntries.getGlobalEntries().getConfigManager().getUpgradeManager();
		
		if (req.getHeader("Connection") != null && req.getHeader("Connection").getValues().get(0).equalsIgnoreCase("Upgrade")) {
			
			ProxyResponse pr = (ProxyResponse) resp.getServletResponse();
			
			upgradeRequestManager.proxyWebSocket(req, (HttpServletResponse) pr.getResponse(),proxyToURL.toString());
			
		} else {
			CloseableHttpClient httpclient = this.getHttp(proxyTo, req.getServletRequest(), holder.getConfig());
			
			//HttpGet httpget = new HttpGet(proxyToURL.toString());
			
			HttpRequestBase httpMethod = new UriMethod(req.getMethod(),proxyToURL.toString());//this.getHttpMethod(proxyToURL.toString());
			
			req.setAttribute("TREMOLO_FINAL_URL", proxyToURL.toString());
			
			setHeadersCookies(req, holder, httpMethod,proxyToURL.toString());

			HttpContext ctx = (HttpContext) req.getSession().getAttribute(ProxySys.HTTP_CTX);
			HttpResponse response = httpclient.execute(httpMethod,ctx);
			
			postProcess(req, resp, holder, response,proxyToURL.toString(),chain,httpMethod);
			
		}
		
		
		
		
		
		
		

	}
	
	

	

	@Override
	public boolean addHeader(String name) {
		return true;
	}

}
