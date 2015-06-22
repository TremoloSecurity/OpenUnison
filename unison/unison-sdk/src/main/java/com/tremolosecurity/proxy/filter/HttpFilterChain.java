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


package com.tremolosecurity.proxy.filter;

import java.io.InputStream;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.HttpRequestBase;

public interface HttpFilterChain {

	public abstract boolean isLogout();

	public abstract void setLogout(boolean logout);

	public abstract void nextFilter(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain)
			throws Exception;

	public abstract void nextFilterResponseText(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain,
			StringBuffer data) throws Exception;

	public abstract void nextFilterResponseBinary(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain,
			byte[] data, int length) throws Exception;

	public abstract void reload();

	public abstract InputStream getIns();

	public abstract void setIns(InputStream ins);

	public abstract boolean isText();

	public abstract void setText(boolean isText);

	public abstract HttpEntity getEntity();

	public abstract void setEntity(HttpEntity entity);

	public abstract void setNoProxy(boolean b);

	public abstract boolean isNoProxy();
	
	public abstract void setHttpRequestBase(HttpRequestBase httpRequest);
	
	public abstract HttpRequestBase getHttpRequestBase();

}