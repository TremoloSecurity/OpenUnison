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


package com.tremolosecurity.proxy.util;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.proxy.myvd.MyVDConnection;

public class FilterNextSys implements NextSys {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(FilterNextSys.class);
	
	FilterChain chain;
	
	public FilterNextSys(FilterChain chain) {
		this.chain = chain;
	}
	
	@Override
	public void nextSys(HttpServletRequest request,
			HttpServletResponse response) throws IOException,ServletException {
		chain.doFilter(request, response);

	}

}
