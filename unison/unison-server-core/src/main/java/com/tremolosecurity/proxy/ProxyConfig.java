package com.tremolosecurity.proxy;

public class ProxyConfig {
	
	public static final String PROXY_CONFIG_REQUEST = "com.tremolosecurity.proxy-config";
	
	int connectionTimeout;
	int requestTimeout;
	int socketTimeout;
	
	
	public ProxyConfig() {
		this.connectionTimeout = 0;
		this.requestTimeout = 0;
		this.socketTimeout = 0;
	}
	
	public int getConnectionTimeout() {
		return connectionTimeout;
	}
	public void setConnectionTimeout(int connectionTimeout) {
		this.connectionTimeout = connectionTimeout;
	}
	public int getRequestTimeout() {
		return requestTimeout;
	}
	public void setRequestTimeout(int requestTimeout) {
		this.requestTimeout = requestTimeout;
	}
	public int getSocketTimeout() {
		return socketTimeout;
	}
	public void setSocketTimeout(int socketTimeout) {
		this.socketTimeout = socketTimeout;
	}
	
	
}
