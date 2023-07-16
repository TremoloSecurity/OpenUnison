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


package com.tremolosecurity.embedd;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.StringTokenizer;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpSession;

import com.tremolosecurity.util.NVP;

public class LocalSessionRequest extends HttpServletRequestWrapper {

	
	
	List<NVP> queryString;
	
	public LocalSessionRequest(HttpServletRequest req) {
		super(req);
		
		this.queryString = new ArrayList<NVP>();
		if (req.getQueryString() != null && ! req.getQueryString().isEmpty()) {
			StringTokenizer toker = new StringTokenizer(req.getQueryString(),"&");
			while (toker.hasMoreTokens()) {
				String qp = toker.nextToken();
				int index = qp.indexOf('=');
				if (index > 0) {
					String name = qp.substring(0,qp.indexOf('='));
					String val;
					try {
						val = URLDecoder.decode(qp.substring(qp.indexOf('=') + 1),"UTf-8");
						this.queryString.add(new NVP(name,val));
					} catch (UnsupportedEncodingException e) {
						
					}
					
				}
			}
		}
	}
	
	
	@Override
	public HttpSession getSession() {
		String x = null;
		x.toString();
		return null;
	}

	@Override
	public HttpSession getSession(boolean arg0) {
		String x = null;
		x.toString();
		return null;
	}

	@Override
	public boolean isRequestedSessionIdFromCookie() {
		return true;
	}

	@Override
	public boolean isRequestedSessionIdFromURL() {
		return false;
	}

	

	@Override
	public boolean isRequestedSessionIdValid() {
		return true;
	}

	public List<NVP> getQueryStringParams() {
		return this.queryString;
	}

}
