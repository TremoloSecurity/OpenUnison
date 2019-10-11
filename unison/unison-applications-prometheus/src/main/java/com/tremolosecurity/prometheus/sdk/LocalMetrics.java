package com.tremolosecurity.prometheus.sdk;

import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;

import io.prometheus.client.CollectorRegistry;

public interface LocalMetrics {

	public void registerMetrics(CollectorRegistry registry,HttpFilterConfig config);
	
	public void addMetrics(HttpFilterRequest request,HttpFilterResponse response,HttpFilterChain chain) throws Exception;
}
