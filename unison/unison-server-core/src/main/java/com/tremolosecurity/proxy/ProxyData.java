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

import java.io.InputStream;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.HttpRequestBase;

import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.filter.PostProcess;


public class ProxyData {
	HttpFilterRequest request;
	HttpFilterResponse response;
	UrlHolder holder;
	
	boolean isText;
	
	InputStream ins;
	PostProcess postProc;
	
	boolean logout;
	
	HttpRequestBase httpRequestBase;
	
	public boolean isLogout() {
		return logout;
	}
	public void setLogout(boolean logout) {
		this.logout = logout;
	}
	public HttpFilterRequest getRequest() {
		return request;
	}
	public void setRequest(HttpFilterRequest request) {
		this.request = request;
	}
	public HttpFilterResponse getResponse() {
		return response;
	}
	public void setResponse(HttpFilterResponse response) {
		this.response = response;
	}
	public UrlHolder getHolder() {
		return holder;
	}
	public void setHolder(UrlHolder holder) {
		this.holder = holder;
	}
	public boolean isText() {
		return isText;
	}
	public void setText(boolean isText) {
		this.isText = isText;
	}
	
	public InputStream getIns() {
		return ins;
	}
	public void setIns(InputStream ins) {
		this.ins = ins;
	}
	public PostProcess getPostProc() {
		return postProc;
	}
	public void setPostProc(PostProcess postProc) {
		this.postProc = postProc;
	}
	public HttpRequestBase getHttpRequestBase() {
		return httpRequestBase;
	}
	public void setHttpRequestBase(HttpRequestBase httpRequestBase) {
		this.httpRequestBase = httpRequestBase;
	}
	
	
}
