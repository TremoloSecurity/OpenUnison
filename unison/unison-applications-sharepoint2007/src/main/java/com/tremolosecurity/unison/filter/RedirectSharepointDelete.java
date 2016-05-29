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


package com.tremolosecurity.unison.filter;

import java.net.URL;
import java.net.URLEncoder;
import java.util.Iterator;

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;

public class RedirectSharepointDelete implements HttpFilter {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(RedirectSharepointDelete.class.getName());
	@Override
	public void doFilter(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		
		
		if (request.getRequestURI().contains("_vti_bin/owssvr.dll") && request.getParameter("Cmd") != null && request.getParameter("Cmd").getValues().get(0).equals("Delete")) {
			
			/*Iterator<String> it = request.getParameterNames();
			while (it.hasNext()) {
				logger.info(it.next());
			}*/
			
			String ID = request.getParameter("ID").getValues().get(0);
			String source = request.getHeader("Referer").getValues().get(0);
			String rootFolder = request.getParameter("ctl00$PlaceHolderSearchArea$ctl01$ctl01").getValues().get(0);
			
			URL url = new URL(rootFolder);
			rootFolder = url.getPath();
			
			
			
			StringBuffer redir = new StringBuffer();
			redir.append(rootFolder).append("/Forms/DispForm.aspx?").append("ID=").append(ID).append("&Source=").append(URLEncoder.encode(source,"UTF-8")).append("&RootFolder=").append(URLEncoder.encode(rootFolder));
			response.sendRedirect(redir.toString());
			chain.setNoProxy(true);
			
		} else {
			chain.nextFilter(request, response, chain);
		}

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
