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


package com.tremolosecurity.proxy.util;

import java.io.IOException;
import java.util.Enumeration;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class EchoRequest implements Filter {

	@Override
	public void destroy() {
		

	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp,
			FilterChain chain) throws IOException, ServletException {
		
		HttpServletRequest request = (HttpServletRequest) req;
		//System.out.println("************************Begin Request******************************");
		//System.out.println("URL : '" + request.getRequestURL() + "'");
		//System.out.println("Method : '" + request.getMethod() + "'");
		//System.out.println("Source IP : '" + request.getRemoteAddr() + "'");
		//System.out.println("Source Port : '" + request.getRemotePort() + "'");
		
		Enumeration<String> enumer = request.getHeaderNames();
		while (enumer.hasMoreElements()) {
			String name = enumer.nextElement();
			Enumeration<String> enumer2 = request.getHeaders(name);
			while (enumer2.hasMoreElements()) {
				String value = enumer2.nextElement();
				//System.out.println("Header : '" + name + "=" + value + "'");
			}
		}
		
		Cookie[] cookies = request.getCookies();
		if (cookies != null) {
			for (Cookie cookie : cookies) {
				//System.out.println("Cookie : '" + cookie.getName() + "=" + cookie.getValue() + "'");
			}
		}
		
		enumer = request.getParameterNames();
		while (enumer.hasMoreElements()) {
			String name = enumer.nextElement();
			String[] vals = request.getParameterValues(name);
			for (String val : vals) {
				//System.out.println("Parameter : '" + name + "=" + val + "'");
			}
		}
		
		
		//System.out.println("************************End Request******************************");
		
		chain.doFilter(req, resp);
		
		

	}

	@Override
	public void init(FilterConfig arg0) throws ServletException {
		

	}

}
