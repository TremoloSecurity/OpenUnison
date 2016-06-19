package com.tremolosecurity.proxy.filters;

import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;

public class SetNoCacheHeaders implements HttpFilter {

	@Override
	public void doFilter(HttpFilterRequest req, HttpFilterResponse resp, HttpFilterChain chain) throws Exception {
		chain.nextFilter(req, resp, chain);
		
		resp.addHeader("Cache-Control", "no-cache, no-store, must-revalidate");
		resp.addHeader("Pragma", "no-cache");
		resp.addHeader("Expires", "0");

	}

	@Override
	public void filterResponseBinary(HttpFilterRequest arg0, HttpFilterResponse arg1, HttpFilterChain arg2, byte[] arg3,
			int arg4) throws Exception {
		

	}

	@Override
	public void filterResponseText(HttpFilterRequest arg0, HttpFilterResponse arg1, HttpFilterChain arg2,
			StringBuffer arg3) throws Exception {
		

	}

	@Override
	public void initFilter(HttpFilterConfig arg0) throws Exception {
		

	}

}
