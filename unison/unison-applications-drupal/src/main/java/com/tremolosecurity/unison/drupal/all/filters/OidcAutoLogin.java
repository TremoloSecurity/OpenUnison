/*******************************************************************************
 * Copyright 2019 Tremolo Security, Inc.
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
package com.tremolosecurity.unison.drupal.all.filters;




import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.saml.Attribute;

public class OidcAutoLogin implements HttpFilter {

	@Override
	public void doFilter(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		
		
		
		
		
		
		if (request.getMethod().equals("GET")) {
		
			String autoPost = "<html>\n" + 
					"<head>\n" + 
					"<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" />\n" + 
					"<title>Logging In</title>\n" + 
					"</head>\n" + 
					"<body onload=\"document.forms[0].submit()\">\n" + 
					"<form method=\"post\" action=\"/user/login\">\n" + 
					"<input name=\"generic\" value=\"Login+with+Generic\" type=\"hidden\"/>\n" + 
					"<input name=\"form_id\" value=\"openid_connect_login_form\" type=\"hidden\"/>\n" + 
					"</form>\n" + 
					"<center>\n" + 
					"<img src=\"/auth/forms/images/ts_logo.png\" /><br />\n" + 
					"<h2>Logging In...</h2>\n" + 
					"</center>\n" + 
					"</body>\n" + 
					"</html>";
			
			response.getWriter().print(autoPost);
			chain.setNoProxy(true);
		} else {
			chain.nextFilter(request, response, chain);
		}

	}

	@Override
	public void filterResponseText(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain,
			StringBuffer data) throws Exception {
		
		

	}

	@Override
	public void filterResponseBinary(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain,
			byte[] data, int length) throws Exception {
		// TODO Auto-generated method stub

	}

	@Override
	public void initFilter(HttpFilterConfig config) throws Exception {
		// TODO Auto-generated method stub

	}

}
