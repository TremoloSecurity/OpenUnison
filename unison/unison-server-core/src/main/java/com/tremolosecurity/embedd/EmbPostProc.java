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


package com.tremolosecurity.embedd;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;

import javax.servlet.FilterChain;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponseWrapper;

import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.message.BasicHeader;
import org.apache.logging.log4j.Logger;

import com.tremolosecurity.config.util.UnisonConfigManagerImpl;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.proxy.ProxyRequest;
import com.tremolosecurity.proxy.ProxySys;
import com.tremolosecurity.proxy.auth.AzSys;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.filter.PostProcess;
import com.tremolosecurity.saml.Attribute;

public class EmbPostProc extends PostProcess {
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(EmbPostProc.class);
	
	FilterChain chain;
	
	@Override
	public void postProcess(HttpFilterRequest req, HttpFilterResponse resp,
			UrlHolder holder,HttpFilterChain curSChain) throws Exception {
		
		
		ProxyRequest pr = (ProxyRequest) req.getServletRequest();
		
		HashMap<String,Attribute> reqHeaders = this.setHeadersCookiesEmb(req);
		EmbRequest embReq = new EmbRequest(req,pr.getSession(true),reqHeaders);
		
		/*Enumeration enumer = embReq.getParameterNames();
		while (enumer.hasMoreElements()) {
			String name = (String) enumer.nextElement();
			logger.info("Parameter : '" + name + "'='" + embReq.getParameter(name) + "'");
		}*/
		
		HttpServletRequestWrapper reqWrapper = new HttpServletRequestWrapper(embReq);
		
		/*enumer = reqWrapper.getHeaderNames();
		while (enumer.hasMoreElements()) {
			String name = (String) enumer.nextElement();
			Enumeration enumer1 = reqWrapper.getHeaders(name);
			while (enumer1.hasMoreElements()) {
				String val = (String) enumer1.nextElement();
				logger.info("wrapper header : '" + name + "'='" + val + "'");
			}
		}*/
		
		
		
		HttpServletResponseWrapper respWrapper = new HttpServletResponseWrapper(resp.getServletResponse());
		
		chain.doFilter(reqWrapper, respWrapper);
		
		
		/*logger.info(resp);
		logger.info(resp.getServletResponse());
		logger.info(resp.getServletResponse().getContentType());*/
		
		/*if (resp.getServletResponse().getContentType() != null && resp.getServletResponse().getContentType().startsWith("text")) {
			req.setAttribute(ProxySys.AUTOIDM_STREAM_WRITER, true);
		} else {
			req.setAttribute(ProxySys.AUTOIDM_STREAM_WRITER, false);
		}*/
		
		//TODO: support content manipulation

	}

	@Override
	public boolean addHeader(String name) {
		return true;
	}
	
	public EmbPostProc(FilterChain chain) {
		this.chain = chain;
	}
	
	
	
	protected HashMap<String,Attribute>  setHeadersCookiesEmb(HttpFilterRequest req) throws Exception {
		Iterator<String> names;
		
		names = req.getHeaderNames();
		
		
		
		HashMap<String,Attribute> reqHeaders = new HashMap<String,Attribute>();
		
		
		
		while (names.hasNext()) {
			String name = names.next();
			if (name.equalsIgnoreCase("Cookie")) {
				
				continue;
			}
			
			if (logger.isDebugEnabled()) {
				logger.debug("Header : " + name);
			}
			
			
			Attribute attrib = req.getHeader(name);
			ArrayList<String> vals = new ArrayList<String>();
			
			vals.addAll(attrib.getValues());
			//logger.info("Header : '" + name + "'='" + vals + "'");
			
			if (name.equalsIgnoreCase("Content-Type")) {
				continue;
			} else if (name.equalsIgnoreCase("If-Range")) {
				continue;
			} else if (name.equalsIgnoreCase("Range")) {
				continue;
			} else if (name.equalsIgnoreCase("If-None-Match")) {
				continue;
			}
			
			if (this.addHeader(name)) {
				Attribute header = reqHeaders.get(name);
				if (header == null) {
					header = new Attribute(name);
					reqHeaders.put(name, header);
				}
				
				header.getValues().addAll(vals);
			}
			
			
		}
		
		
		HashMap<String,Attribute> fromResults = (HashMap<String,Attribute>) req.getAttribute(AzSys.AUTO_IDM_HTTP_HEADERS);
		if (fromResults != null) {
			names = fromResults.keySet().iterator();
			
			while (names.hasNext()) {
				String name = names.next();
				reqHeaders.remove(name);
				
				Attribute attrib = fromResults.get(name);
				
				
				
				Attribute header = reqHeaders.get(name);
				if (header == null) {
					header = new Attribute(name);
					reqHeaders.put(name, header);
				}
				
				
				
				header.getValues().addAll(attrib.getValues());
				
				//logger.info("Header2 : '" + name + "'='" + header.getValues() + "'");
			}
		}
		
		return reqHeaders;
		
		
	}

}
