/*******************************************************************************
 * Copyright (c) 2024 Tremolo Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package com.tremolosecurity.proxy;

import java.io.IOException;

import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterChainImpl;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterRequestImpl;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.filter.HttpFilterResponseImpl;
import com.tremolosecurity.proxy.util.NextSys;
import com.tremolosecurity.proxy.util.ProxyConstants;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

public class InternalNextSys implements NextSys {
	
	ProcessAfterFilterChain postProc;
	
	public InternalNextSys(ProcessAfterFilterChain postProc) {
		this.postProc = postProc;
	}

	@Override
	public void nextSys(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		
		
		HttpSession session = request.getSession();
		
		AuthController ac = (AuthController) session.getAttribute(ProxyConstants.AUTH_CTL);
		if (ac == null) {
			ac = new AuthController();
			session.setAttribute(ProxyConstants.AUTH_CTL, ac);
		}
		
		if (ac.getAuthInfo() == null) {
			AuthInfo authInfo = new AuthInfo("cn=Anonymous","anonymous","anonymous",0,null);
			ac.setAuthInfo(new AuthInfo());
			
		}
		
		if (ac.getAuthInfo().getUserDN() == null) {
			ac.getAuthInfo().setUserDN("cn=Anonymous",null);
		}
		
		
		
		HttpFilterRequest filterReq = new HttpFilterRequestImpl(request, null);
		HttpFilterResponse filterResp = new HttpFilterResponseImpl(response);

				
		HttpFilterChain chain = new HttpFilterChainImpl(holder,postProc);
		try {
			chain.nextFilter(filterReq, filterResp, chain);
		} catch (Exception e) {
			
			throw new ServletException(e);
		}

	}

}
