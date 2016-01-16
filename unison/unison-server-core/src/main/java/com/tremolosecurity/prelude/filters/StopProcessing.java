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


package com.tremolosecurity.prelude.filters;

import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;




public class StopProcessing implements HttpFilter {

	@Override
	public void doFilter(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		chain.setNoProxy(true);
		

	}

	@Override
	public void filterResponseText(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain,
			StringBuffer data) throws Exception {
		

	}

	@Override
	public void filterResponseBinary(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain, byte[] data,
			int length) throws Exception {
		

	}

	@Override
	public void initFilter(HttpFilterConfig config) throws Exception {
		

	}

}
