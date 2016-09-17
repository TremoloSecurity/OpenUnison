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

import javax.servlet.http.Cookie;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthMgrSys;
import com.tremolosecurity.proxy.auth.AuthSys;
import com.tremolosecurity.proxy.auth.LoginService;
import com.tremolosecurity.proxy.auth.RequestHolder;
import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.proxy.util.ProxyTools;



public class CompleteLogin implements HttpFilter {

	@Override
	public void doFilter(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		
		RequestHolder reqHolder = (RequestHolder) request.getSession().getAttribute(LoginService.ORIG_REQ_HOLDER);
		((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).setHolder(reqHolder);
		StringBuffer redirURL;
		
		ConfigManager cfg = (ConfigManager) request.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);
		
		
		redirURL = cfg.getAuthManager().getGetRedirectURL(reqHolder);
		
		
		/*
		switch (reqHolder.getMethod()) {
		
			case GET :  redirURL = cfg.getAuthManager().getGetRedirectURL(reqHolder);
						break;
						
			case POST : redirURL = (new StringBuffer(cfg.getAuthFormsPath())).append("/postPreservation.jsp");
						break;
						
			default : redirURL = new StringBuffer(reqHolder.getURL());
		}*/
	
	
		response.sendRedirect(redirURL.toString());
		
		
		chain.setNoProxy(true);

	}

	@Override
	public void filterResponseText(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain,
			StringBuffer data) throws Exception {
		chain.nextFilterResponseText(request, response, chain, data);

	}

	@Override
	public void filterResponseBinary(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain, byte[] data,
			int length) throws Exception {
		chain.nextFilterResponseBinary(request, response, chain, data, length);

	}

	@Override
	public void initFilter(HttpFilterConfig config) throws Exception {
		

	}

}
