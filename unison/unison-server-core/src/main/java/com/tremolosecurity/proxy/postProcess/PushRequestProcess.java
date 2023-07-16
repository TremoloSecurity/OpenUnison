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
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

import jakarta.servlet.http.HttpServletRequest;

import org.apache.commons.fileupload2.core.FileItem;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.ProtocolException;
import org.apache.http.client.CookieStore;
import org.apache.http.client.RedirectHandler;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.params.ClientPNames;
import org.apache.http.client.params.CookiePolicy;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.cookie.Cookie;
import org.apache.http.cookie.CookieOrigin;
import org.apache.http.cookie.CookieSpec;
import org.apache.http.cookie.CookieSpecFactory;
import org.apache.http.cookie.MalformedCookieException;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.mime.HttpMultipartMode;
import org.apache.http.entity.mime.MultipartEntity;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.InputStreamBody;
import org.apache.http.entity.mime.content.StringBody;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.cookie.BrowserCompatSpec;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.HttpContext;
import org.apache.logging.log4j.Logger;

import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.proxy.ProxySys;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.filter.PostProcess;
import com.tremolosecurity.proxy.http.EntityMethod;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.util.NVP;

public  class PushRequestProcess extends PostProcess {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(PushRequestProcess.class);

	@Override
	public void postProcess(HttpFilterRequest req, HttpFilterResponse resp,UrlHolder holder,HttpFilterChain chain) throws Exception {
		boolean isText;
		
		
		
		HashMap<String,String> uriParams = (HashMap<String,String>) req.getAttribute("TREMOLO_URI_PARAMS");
		
		StringBuffer proxyToURL = new StringBuffer();
		
		proxyToURL.append(holder.getProxyURL(uriParams));
		
		
		
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
		
		
		HttpEntity entity = null;
		
		
		
		if (req.isMultiPart()) {
			
			MultipartEntityBuilder mpeb = MultipartEntityBuilder.create().setMode(HttpMultipartMode.BROWSER_COMPATIBLE);
			
			
			
			
			
			for (String name : req.getFormParams()) {
				
				/*if (queryParams.contains(name)) {
					continue;
				}*/
				
				
				for (String val : req.getFormParamVals(name)) {
					//ent.addPart(name, new StringBody(val));
					mpeb.addTextBody(name, val);
				}
				
			}
			
			HashMap<String,ArrayList<FileItem>> files = req.getFiles();
			for (String name : files.keySet()) {
				for (FileItem fi : files.get(name)) {
					//ent.addPart(name, new InputStreamBody(fi.getInputStream(),fi.getContentType(),fi.getName()));
					
					
					
					mpeb.addBinaryBody(name, fi.get(),ContentType.create(fi.getContentType()),fi.getName());
				
				}
			}
			
			
			
			entity = mpeb.build();
			
		} else if (req.isParamsInBody()) {
			List<NameValuePair> formparams = new ArrayList<NameValuePair>();
			
			for (String paramName : req.getFormParams()) {
				
				
				for (String val : req.getFormParamVals(paramName)) {
					
					formparams.add(new BasicNameValuePair(paramName, val));
				}
			}
			
			
			
			entity = new UrlEncodedFormEntity(formparams, "UTF-8");
		} else {
		
			byte[] msgData = (byte[]) req.getAttribute(ProxySys.MSG_BODY);
			ByteArrayEntity bentity = new ByteArrayEntity(msgData);
			bentity.setContentType(req.getContentType());
		
			entity = bentity;
		}
		
		
		
	
		
		CloseableHttpClient httpclient = this.getHttp(proxyToURL.toString(), req.getServletRequest(), holder);
		
		
		
		//HttpPost httppost = new HttpPost(proxyToURL.toString());
		HttpEntityEnclosingRequestBase httpMethod = new EntityMethod(req.getMethod(),proxyToURL.toString());//this.getHttpMethod(proxyToURL.toString());
		
		
		setHeadersCookies(req, holder, httpMethod,proxyToURL.toString());
		
		
		
		
		
		httpMethod.setEntity(entity);
		
		HttpContext ctx = (HttpContext) req.getSession().getAttribute(ProxySys.HTTP_CTX);
		HttpResponse response = httpclient.execute(httpMethod,ctx);
		
		
		
		postProcess(req, resp, holder, response,proxyToURL.toString(),chain,httpMethod);
		
	}

	

	@Override
	public boolean addHeader(String name) {
		if (name.equalsIgnoreCase("Content-Length")) {
			return false;
		} else {
			return true;
		}
	}
}
