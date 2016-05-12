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


package com.tremolosecurity.proxy.auth.util;

import java.io.IOException;
import java.security.Principal;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthScheme;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.AuthCache;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.params.ClientPNames;
import org.apache.http.client.protocol.ClientContext;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.cookie.Cookie;
import org.apache.http.cookie.CookieOrigin;
import org.apache.http.cookie.CookieSpec;
import org.apache.http.cookie.CookieSpecFactory;
import org.apache.http.cookie.MalformedCookieException;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.auth.BasicSchemeFactory;
import org.apache.http.impl.client.BasicAuthCache;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.impl.cookie.BrowserCompatSpec;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.BasicHttpContext;

import com.google.gson.Gson;
import com.novell.ldap.LDAPException;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.AuthMechType;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.filter.PostProcess;
import com.tremolosecurity.proxy.myvd.MyVDConnection;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.server.GlobalEntries;

public class HttpBasicAuth implements BasicAuthImpl {

	String url;

	boolean ssl;
	int port;
	String host;

	public HttpBasicAuth(String url, boolean ssl, String host, int port) {
		this.url = url;

		this.ssl = ssl;
		this.port = port;
		this.host = host;
	}

	@Override
	public void doAuth(HttpServletRequest request, HttpSession session,
			String uidAttr, final String userName, final String password,
			MyVDConnection myvd, AuthChainType act, AuthMechType amt,
			AuthStep as,ConfigManager cfgMgr) throws LDAPException {

		
		BasicHttpClientConnectionManager bhcm = new BasicHttpClientConnectionManager(
				cfgMgr.getHttpClientSocketRegistry());
		try {

			AuthCache authCache = new BasicAuthCache();
			BasicScheme basicAuth = new BasicScheme();
			HttpHost targetHost = new HttpHost(this.host, this.port);
			authCache.put(targetHost, basicAuth);
			HttpClientContext localcontext = HttpClientContext.create();
			localcontext.setAuthCache(authCache);

			Credentials user = new UsernamePasswordCredentials(userName,
					password);
			AuthScope scope = new AuthScope(this.host, this.port);
			CredentialsProvider credsProvider = new BasicCredentialsProvider();
			credsProvider.setCredentials(scope, user);

			CloseableHttpClient httpclient = HttpClients.custom()
					.setConnectionManager(bhcm)
					.setDefaultCredentialsProvider(credsProvider).build();

			HttpGet get = new HttpGet(this.url);

			try {
				HttpResponse res = httpclient.execute(targetHost, get,
						localcontext);
				if (res.getFirstHeader("UserJSON") != null) {
					String json = res.getFirstHeader("UserJSON").getValue();
					Gson gson = new Gson();
					AuthInfo authInfo = gson.fromJson(json, AuthInfo.class);
					StringBuffer b = new StringBuffer();
					b.append("uid=").append(userName).append(",").append(GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getLdapRoot());
					authInfo.setUserDN(b.toString());
					authInfo.setAuthChain(act.getName());
					authInfo.setAuthLevel(act.getLevel());

					as.setExecuted(true);
					as.setSuccess(true);

					AuthController actl = (AuthController) session
							.getAttribute(ProxyConstants.AUTH_CTL);
					if (actl == null) {
						actl = new AuthController();
						session.setAttribute(ProxyConstants.AUTH_CTL, actl);
					}

					actl.setAuthInfo(authInfo);
				}
			} catch (Exception e) {
				throw new LDAPException("Could not authenticate user",
						LDAPException.OPERATIONS_ERROR, e.toString(), e);
			}

		} finally {
			bhcm.shutdown();
		}
	}

}
