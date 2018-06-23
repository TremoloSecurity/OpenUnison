
package com.tremolosecurity.proxy.filters;

import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;

/**
 * NoRedirectOnError
 */
public class NoRedirectOnError implements HttpFilter {

	@Override
	public void doFilter(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
                request.getServletRequest().setAttribute("com.tremolosecurity.unison.proxy.noRedirectOnError", "com.tremolosecurity.unison.proxy.noRedirectOnError");
                chain.nextFilter(request, response, chain);
	}

	@Override
	public void filterResponseText(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain,
			StringBuffer data) throws Exception {
		
	}

	@Override
	public void filterResponseBinary(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain,
			byte[] data, int length) throws Exception {
		
	}

	@Override
	public void initFilter(HttpFilterConfig config) throws Exception {
		
	}

    
}