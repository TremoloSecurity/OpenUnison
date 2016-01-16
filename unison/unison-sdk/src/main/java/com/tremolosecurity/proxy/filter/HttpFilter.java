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

public interface HttpFilter {

	public void doFilter(HttpFilterRequest request,HttpFilterResponse response,HttpFilterChain chain) throws Exception;
	
	public void filterResponseText(HttpFilterRequest request,HttpFilterResponse response,HttpFilterChain chain,StringBuffer data) throws Exception;
	
	public void filterResponseBinary(HttpFilterRequest request,HttpFilterResponse response,HttpFilterChain chain,byte[] data,int length) throws Exception;
	
	public void initFilter(HttpFilterConfig config) throws Exception;
	
}
