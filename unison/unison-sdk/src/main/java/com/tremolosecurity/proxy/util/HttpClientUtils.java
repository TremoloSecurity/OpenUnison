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

import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;

import com.tremolosecurity.config.util.ConfigManager;

public class HttpClientUtils {

	
	
	public static HttpClient createSingleClient(ConfigManager cfg) {
		BasicHttpClientConnectionManager bhcm = new BasicHttpClientConnectionManager(cfg.getHttpClientSocketRegistry());
		
		CloseableHttpClient httpclient = HttpClients.custom().setConnectionManager(bhcm).build();
		
		return httpclient;
	}
	
	public static PoolingHttpClientConnectionManager createPooledConnectionManager(ConfigManager cfg) {
		PoolingHttpClientConnectionManager phcm = new PoolingHttpClientConnectionManager(cfg.getHttpClientSocketRegistry());
		return phcm;
	}
	
}
