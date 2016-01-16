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


package com.tremolosecurity.proxy;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.HashSet;
import java.util.StringTokenizer;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.embedd.EmbPostProc;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterChainImpl;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterRequestImpl;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.filter.HttpFilterResponseImpl;
import com.tremolosecurity.proxy.filter.PostProcess;
import com.tremolosecurity.proxy.postProcess.PushRequestProcess;
import com.tremolosecurity.proxy.postProcess.UriRequestProcess;
import com.tremolosecurity.proxy.util.ProxyConstants;

public class ProxySys {

	static Logger logger = Logger.getLogger(ProxySys.class);

	public static String TREMOLO_BINARY_DATA = "TREMOLO_BINARY_DATA";
	
	public static final String AUTOIDM_STREAM_WRITER = "AUTOIDM_STREAM_WRITER";

	public static final String TREMOLO_TXT_DATA = "TREMOLO_TXT_DATA";

	public static final String QUERY_PARAMS = "TREMOLO_PROXY_QUERY_PARAMS";

	public static final String MSG_BODY = "TREMOLO_PROXY_MSG_BODY";

	
	public void doURI(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		boolean isText = false;

		UrlHolder holder = (UrlHolder) req.getAttribute(ProxyConstants.AUTOIDM_CFG);

		HashMap<String,String> uriParams = (HashMap<String,String>) req.getAttribute("TREMOLO_URI_PARAMS");
		if (uriParams == null) {
			uriParams = new HashMap<String,String>();
			req.setAttribute("TREMOLO_URI_PARAMS", uriParams);
		}
		
		uriParams.put("fullURI", req.getRequestURI());
		
		HttpFilterRequest filterReq = new HttpFilterRequestImpl(req, null);
		HttpFilterResponse filterResp = new HttpFilterResponseImpl(resp);

		PostProcess postProc = null;
		
		if (holder.getUrl().getProxyTo() == null || holder.getUrl().getProxyTo().isEmpty()) {
			FilterChain filterChain = (FilterChain) req.getAttribute(ProxyConstants.TREMOLO_FILTER_CHAIN);
			if (filterChain == null) {
				logger.warn("Could not find filter chain");
			}
			postProc = new EmbPostProc(filterChain);
		} else {
			postProc = new UriRequestProcess(); 
		}
		
		
		HttpFilterChain chain = new HttpFilterChainImpl(holder,
				postProc);
		try {
			chain.nextFilter(filterReq, filterResp, chain);
		} catch (Exception e) {
			
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			PrintWriter err = new PrintWriter(new OutputStreamWriter(baos));
			
			e.printStackTrace(err);
			Throwable t = e.getCause();
			while (t != null) {
				t.printStackTrace(err);
				t = t.getCause();
			}
			
			logger.error("Error Executing Request : " + new String(baos.toByteArray()));
			
			throw new ServletException("Could not execute request",e);
		}
		
		ProxyData pd = new ProxyData();
		
		pd.setHolder(holder);
		pd.setIns(chain.getIns());
		pd.setPostProc(postProc);
		pd.setRequest(filterReq);
		pd.setResponse(filterResp);
		pd.setText(chain.isText());
		pd.setLogout(chain.isLogout());
		pd.setHttpRequestBase(chain.getHttpRequestBase());
		
		req.setAttribute(ProxyConstants.TREMOLO_PRXY_DATA, pd);
		
	}
	
	public void doPush(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {

		UrlHolder holder = (UrlHolder) req.getAttribute(ProxyConstants.AUTOIDM_CFG);

		HttpFilterRequest filterReq = new HttpFilterRequestImpl(req, null);
		HttpFilterResponse filterResp = new HttpFilterResponseImpl(resp);

		HashMap<String,String> uriParams = (HashMap<String,String>) req.getAttribute("TREMOLO_URI_PARAMS");
		if (uriParams == null) {
			uriParams = new HashMap<String,String>();
			req.setAttribute("TREMOLO_URI_PARAMS", uriParams);
		}
		
		uriParams.put("fullURI", req.getRequestURI());
		
		HashSet<String> queryParams = new HashSet<String>();

		req.setAttribute(ProxySys.QUERY_PARAMS, queryParams);

		String qs = req.getQueryString();
		if (qs != null) {
			StringTokenizer toker = new StringTokenizer(qs, "&", false);
			while (toker.hasMoreTokens()) {
				String qsParam = toker.nextToken();
				String paramName = qsParam.substring(0, qsParam.indexOf('='));
				if (!queryParams.contains(paramName)) {
					queryParams.add(paramName);
				}
			}
		}
		
		
		PostProcess postProc = null;
		
		if (holder.getUrl().getProxyTo() == null || holder.getUrl().getProxyTo().isEmpty()) {
			FilterChain filterChain = (FilterChain) req.getAttribute(ProxyConstants.TREMOLO_FILTER_CHAIN);
			if (filterChain == null) {
				logger.warn("Could not find filter chain");
			}
			postProc = new EmbPostProc(filterChain);
		} else {
			postProc = new PushRequestProcess();;
		}
		
		
		 

		HttpFilterChain chain = new HttpFilterChainImpl(holder,
				postProc);
		try {
			chain.nextFilter(filterReq, filterResp, chain);
		} catch (Exception e) {

			throw new ServletException(e);
		}
		
		ProxyData pd = new ProxyData();
		
		pd.setHolder(holder);
		pd.setIns(chain.getIns());
		pd.setPostProc(postProc);
		pd.setRequest(filterReq);
		pd.setResponse(filterResp);
		pd.setText(chain.isText());
		pd.setLogout(chain.isLogout());
		pd.setHttpRequestBase(chain.getHttpRequestBase());
		
		req.setAttribute(ProxyConstants.TREMOLO_PRXY_DATA, pd);
	}
	
	

}
