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


package com.tremolosecurity.proxy.filter;

import java.io.InputStream;
import java.util.Iterator;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.logging.log4j.Logger;

import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.proxy.HttpProxy;
import com.tremolosecurity.proxy.TremoloHttpSession;
import com.tremolosecurity.proxy.auth.RequestHolder.HTTPMethod;

public class HttpFilterChainImpl implements HttpFilterChain {
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(HttpFilterChainImpl.class);
	
	Iterator<HttpFilter> chain;
	//HttpProxy proxy;
	UrlHolder holder;
	PostProcess postProcess;
	InputStream ins;
	boolean isText;
	HttpEntity entity;
	HttpRequestBase httpRequest;
	
	boolean logout;

	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterChain#isLogout()
	 */
	@Override
	public boolean isLogout() {
		return logout;
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterChain#setLogout(boolean)
	 */
	@Override
	public void setLogout(boolean logout) {
		this.logout = logout;
	}

	private boolean noProxy;

	public HttpFilterChainImpl(UrlHolder holder,PostProcess postProcess) {
		this.holder = holder;
		this.postProcess = postProcess;
		
		
		this.logout = false;
		this.noProxy = false;
		
		if (holder.getFilterChain() != null) {
			this.chain = holder.getFilterChain().iterator();
		} else {
			this.chain = null;
		}
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterChain#nextFilter(com.tremolosecurity.proxy.filter.HttpFilterRequestImpl, com.tremolosecurity.proxy.filter.HttpFilterResponseImpl, com.tremolosecurity.proxy.filter.HttpFilterChain)
	 */
	@Override
	public void nextFilter(HttpFilterRequest request,HttpFilterResponse response,HttpFilterChain chain) throws Exception {
		if (this.chain != null && this.chain.hasNext()) {
			this.chain.next().doFilter(request, response, chain);
		} else {
			
			
			
			
			postProcess.postProcess(request, response, holder,this);
		}
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterChain#nextFilterResponseText(com.tremolosecurity.proxy.filter.HttpFilterRequestImpl, com.tremolosecurity.proxy.filter.HttpFilterResponseImpl, com.tremolosecurity.proxy.filter.HttpFilterChain, java.lang.StringBuffer)
	 */
	@Override
	public void nextFilterResponseText(HttpFilterRequest request,HttpFilterResponse response,HttpFilterChain chain,StringBuffer data) throws Exception  {
		if (this.chain != null && this.chain.hasNext()) {
			this.chain.next().filterResponseText(request, response, chain, data);
		}
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterChain#nextFilterResponseBinary(com.tremolosecurity.proxy.filter.HttpFilterRequestImpl, com.tremolosecurity.proxy.filter.HttpFilterResponseImpl, com.tremolosecurity.proxy.filter.HttpFilterChain, byte[], int)
	 */
	@Override
	public void nextFilterResponseBinary(HttpFilterRequest request,HttpFilterResponse response,HttpFilterChain chain,byte[] data,int length) throws Exception  {
		if (this.chain != null && this.chain.hasNext()) {
			this.chain.next().filterResponseBinary(request, response, chain, data, length);
		}
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterChain#reload()
	 */
	@Override
	public void reload() {
		if (holder.getFilterChain() != null) {
			this.chain = holder.getFilterChain().iterator();
		} else {
			this.chain = null;
		}
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterChain#getIns()
	 */
	@Override
	public InputStream getIns() {
		return ins;
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterChain#setIns(java.io.InputStream)
	 */
	@Override
	public void setIns(InputStream ins) {
		this.ins = ins;
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterChain#isText()
	 */
	@Override
	public boolean isText() {
		return isText;
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterChain#setText(boolean)
	 */
	@Override
	public void setText(boolean isText) {
		this.isText = isText;
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterChain#getEntity()
	 */
	@Override
	public HttpEntity getEntity() {
		return entity;
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterChain#setEntity(org.apache.http.HttpEntity)
	 */
	@Override
	public void setEntity(HttpEntity entity) {
		this.entity = entity;
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterChain#setNoProxy(boolean)
	 */
	@Override
	public void setNoProxy(boolean b) {
		this.noProxy = true;
		
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.filter.HttpFilterChain#isNoProxy()
	 */
	@Override
	public boolean isNoProxy() {
		return this.noProxy;
	}

	@Override
	public void setHttpRequestBase(HttpRequestBase httpRequest) {
		this.httpRequest = httpRequest;
		
	}

	@Override
	public HttpRequestBase getHttpRequestBase() {
		return this.httpRequest;
	}
	
	
}
