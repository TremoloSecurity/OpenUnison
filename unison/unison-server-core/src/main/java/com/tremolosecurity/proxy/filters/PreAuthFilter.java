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

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpCookie;
import java.net.URI;
import java.net.URL;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpSession;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.ProtocolException;
import org.apache.http.client.CookieStore;
import org.apache.http.client.RedirectHandler;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.params.ClientPNames;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.cookie.CookieOrigin;
import org.apache.http.cookie.CookieSpec;
import org.apache.http.cookie.CookieSpecFactory;
import org.apache.http.cookie.MalformedCookieException;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.impl.cookie.BrowserCompatSpec;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.HttpContext;
import org.apache.logging.log4j.Logger;
import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.ConfigurationException;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.ApplicationType;
import com.tremolosecurity.config.xml.FilterConfigType;
import com.tremolosecurity.config.xml.IdpType;
import com.tremolosecurity.config.xml.ParamType;
import com.tremolosecurity.config.xml.TrustType;
import com.tremolosecurity.config.xml.UrlType;
import com.tremolosecurity.idp.providers.Saml2Idp;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.util.LastMileUtil;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Saml2Assertion;


public class PreAuthFilter implements HttpFilter {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(PreAuthFilter.class.getName());
	
	String url;
	String loginAttribute;
	String headerName;
	String lastMileKeyAlias;
	String uri;
	
	boolean postSAML;
	boolean signResponse;
	boolean signAssertion;
	String keyAlias;
	String assertionConsumerURL;
	String nameIDType;
	String nameIDAttribute;
	String authnCtxClassRef;
	String issuer;
	String audience;
	String relayState;
	
	
	@Override
	public void doFilter(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
		ConfigManager cfg = (ConfigManager) request.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);
		
		
		List<Cookie> cookies = null;
		
		if (userData.getAuthLevel() > 0 && userData.isAuthComplete()) {
			UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
			HttpSession session = request.getSession();
			String uid = (String) session.getAttribute("TREMOLO_PRE_AUTH");
			if (uid == null || ! uid.equals(userData.getUserDN())) {
				session.setAttribute("TREMOLO_PRE_AUTH", userData.getUserDN());
				HashMap<String,String> uriParams = new HashMap<String,String>();
				uriParams.put("fullURI", this.uri);
				
				UrlHolder remHolder = cfg.findURL(this.url);
				
				org.apache.http.client.methods.HttpRequestBase method = null;
				
				
				
				if (this.postSAML) {
					PrivateKey pk = holder.getConfig().getPrivateKey(this.keyAlias);
					java.security.cert.X509Certificate cert = holder.getConfig().getCertificate(this.keyAlias);
					
					Saml2Assertion assertion = new Saml2Assertion(userData.getAttribs().get(this.nameIDAttribute).getValues().get(0),pk,cert,null,this.issuer,this.assertionConsumerURL,this.audience,this.signAssertion,this.signResponse,false,this.nameIDType,this.authnCtxClassRef);
					
					String respXML = "";
					
					try {
						respXML = assertion.generateSaml2Response();
					} catch (Exception e) {
						throw new ServletException("Could not generate SAMLResponse",e);
					}
					
					List<NameValuePair> formparams = new ArrayList<NameValuePair>();
					String base64 = Base64.encodeBase64String(respXML.getBytes("UTF-8"));
					
					formparams.add(new BasicNameValuePair("SAMLResponse",base64));
					if (this.relayState != null && ! this.relayState.isEmpty()) {
						formparams.add(new BasicNameValuePair("RelayState",this.relayState));
					}
					
					UrlEncodedFormEntity entity = new UrlEncodedFormEntity(formparams, "UTF-8");
					HttpPost post = new HttpPost(this.assertionConsumerURL);
					post.setEntity(entity);
					method = post;
					
				} else {
					HttpGet get = new HttpGet(remHolder.getProxyURL(uriParams));
					method = get;
				}
				
				
				LastMileUtil.addLastMile(cfg, userData.getAttribs().get(loginAttribute).getValues().get(0), this.loginAttribute, method, lastMileKeyAlias, true);
				BasicHttpClientConnectionManager bhcm = new BasicHttpClientConnectionManager(cfg.getHttpClientSocketRegistry());			
				try {
					CloseableHttpClient httpclient = HttpClients.custom().setConnectionManager(bhcm).setDefaultRequestConfig(cfg.getGlobalHttpClientConfig()).build();
					
					HttpResponse resp = httpclient.execute(method);
					
					if (resp.getStatusLine().getStatusCode() == 500) {
						BufferedReader in = new BufferedReader(new InputStreamReader(resp.getEntity().getContent()));
						StringBuffer error = new StringBuffer();
						String line = null;
						while ((line = in.readLine()) != null) {
							error.append(line).append('\n');
						}
						
						logger.warn("Pre-Auth Failed : " + error);
					}
					
					org.apache.http.Header[] headers = resp.getAllHeaders();
					
					
					StringBuffer stmp = new StringBuffer();
					
					cookies = new ArrayList<Cookie>();
					
					for (org.apache.http.Header header : headers) {
						if (header.getName().equalsIgnoreCase("set-cookie") || header.getName().equalsIgnoreCase("set-cookie2")) {
							//System.out.println(header.getValue());
							String cookieVal = header.getValue();
							/*if (cookieVal.endsWith("HttpOnly")) {
								cookieVal = cookieVal.substring(0,cookieVal.indexOf("HttpOnly"));
							}
							
							//System.out.println(cookieVal);*/
							
							List<HttpCookie> cookiesx = HttpCookie.parse(cookieVal);
							for (HttpCookie cookie : cookiesx) {
								
								String cookieFinalName = cookie.getName();
								if (cookieFinalName.equalsIgnoreCase("JSESSIONID")) {
									stmp.setLength(0);
									stmp.append("JSESSIONID").append('-').append(holder.getApp().getName().replaceAll(" ", "|"));
									cookieFinalName = stmp.toString();
								}
								
								//logger.info("Adding cookie name '" + cookieFinalName + "'='" + cookie.getValue() + "'");
								
								Cookie respcookie = new Cookie(cookieFinalName, cookie.getValue());
								respcookie.setComment(cookie.getComment());
								if (cookie.getDomain() != null) {
									//respcookie.setDomain(cookie.getDomain());
								}
								respcookie.setMaxAge((int) cookie.getMaxAge());
								respcookie.setPath(cookie.getPath());
								
								respcookie.setSecure(cookie.getSecure());
								respcookie.setVersion(cookie.getVersion());
								cookies.add(respcookie);
								
								if (request.getCookieNames().contains(respcookie.getName())) {
									request.removeCookie(cookieFinalName);
								}
								
								request.addCookie(new Cookie(cookie.getName(),cookie.getValue()));
							}
						}
					}
				
				} finally {
					bhcm.shutdown();
				}
			}
		}
		
		chain.nextFilter(request, response, chain);
		if (cookies != null) {
			
			
			
			
			for (Cookie cookie : cookies) {
				
				response.addCookie(cookie);
			}
		}

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
		this.postSAML = config.getAttribute("postSAML") != null && config.getAttribute("postSAML").getValues().get(0).equalsIgnoreCase("true");
		
		
		
		
		
		
		if (postSAML) {
			String idpName = config.getAttribute("idpName").getValues().get(0);
			ApplicationType app = config.getConfigManager().getApp(idpName);
			IdpType idp = app.getUrls().getUrl().get(0).getIdp();
			
			for (ParamType pt : idp.getParams()) {
				if (pt.getName().equalsIgnoreCase("sigKey")) {
					this.keyAlias = pt.getValue();
				}
			}
			
			TrustType tt = idp.getTrusts().getTrust().get(0);
			
			for (ParamType pt : tt.getParam()) {
				if (pt.getName().equalsIgnoreCase("signResponse")) {
					this.signResponse = pt.getValue().equalsIgnoreCase("true");
				} else if (pt.getName().equalsIgnoreCase("signAssertion")) {
					this.signAssertion = pt.getValue().equalsIgnoreCase("true");
				} else if (pt.getName().equalsIgnoreCase("httpPostRespURL")) {
					this.assertionConsumerURL = pt.getValue();
				} else if (pt.getName().equalsIgnoreCase("defaultNameId")) {
					this.nameIDType = pt.getValue();
				} else if (pt.getName().equalsIgnoreCase("nameIdMap")) {
					this.nameIDAttribute = pt.getValue().substring(pt.getValue().indexOf('=') + 1);
				} else if (pt.getName().equalsIgnoreCase("defaultAuthCtx")) {
					this.authnCtxClassRef = pt.getValue();
				} 
					
			}
			
			
			String issuerHost = config.getAttribute("issuerHost").getValues().get(0);
			String issuerPort = config.getAttribute("issuerPort").getValues().get(0);
			boolean issuerSSL = config.getAttribute("issuerSSL").getValues().get(0).equalsIgnoreCase("true");
			
			StringBuffer b = new StringBuffer();
			
			if (issuerSSL) {
				b.append("https://");
			} else {
				b.append("http://");
			}
			
			b.append(issuerHost);
			
			
			if (! issuerPort.isEmpty()) {
				b.append(':').append(issuerPort);
				
			}
			
			b.append("/auth/idp/").append(idpName);
			this.issuer = b.toString();
			
			//this.issuer = config.getAttribute("issuer").getValues().get(0);
			this.audience = tt.getName();
			this.relayState = config.getAttribute("relayState").getValues().get(0);
			
			try {
				DefaultBootstrap.bootstrap();
			} catch (ConfigurationException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		
			this.url = this.assertionConsumerURL;
		} else {
			this.url = config.getAttribute("url").getValues().get(0);
		}
		

		
		URL nurl = new URL(this.url);
		this.uri = nurl.getPath();
		
		UrlType urlCfg = config.getConfigManager().findURL(this.url).getUrl();
		for (FilterConfigType filterCfg : urlCfg.getFilterChain().getFilter()) {
			if (filterCfg.getClazz().equalsIgnoreCase("com.tremolosecurity.proxy.filters.LastMile")) {
				for (ParamType pt : filterCfg.getParam()) {
					if (pt.getName().equalsIgnoreCase("encKeyAlias")) {
						this.lastMileKeyAlias = pt.getValue();
					} else if (pt.getName().equalsIgnoreCase("headerName")) {
						this.headerName = pt.getValue();
					} else if (pt.getName().equalsIgnoreCase("userAttribute")) {
						this.loginAttribute = pt.getValue();
					}
				}
				
				for (ParamType pt : filterCfg.getParam()) {
					if (pt.getName().equalsIgnoreCase("attribs")) {
						String param = pt.getValue();
						String fromUser = param.substring(0,param.indexOf('='));
						String toApp = param.substring(param.indexOf('=') + 1);
						
						if (fromUser.equalsIgnoreCase(this.headerName)) {
							this.headerName = toApp;
						}
						
					} 
				}
			}
		}
		
		
		logger.info("URL : '" + this.url + "'");
		logger.info("Key Alias : '" + this.lastMileKeyAlias + "'");
		logger.info("Login ID Attribute : '" + this.loginAttribute + "'");
		logger.info("Header Attribute : '" + this.headerName + "'");
		
		if (this.postSAML) {
			logger.info("Saml : true");
			logger.info("Issuer : " + this.issuer);
		}
		

	}

}
