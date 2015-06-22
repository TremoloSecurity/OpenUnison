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


package com.tremolosecurity.proxy.auth;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.apache.log4j.Logger;

import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.proxy.TremoloHttpSession;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.util.NVP;

public class RequestHolder implements Serializable {
	


		
	/**
	 * 
	 */
	private static final long serialVersionUID = -3250778433069457390L;

	public boolean isForceAuth() {
		return isForceAuth;
	}

	static Logger logger = Logger.getLogger(RequestHolder.class);
	
	/**
	 * 
	 */
	

	public HTTPMethod getMethod() {
		return method;
	}

	public HashMap<String, Attribute> getParams() {
		return params;
	}

	public String getURL() {
		return URL;
	}

	public enum HTTPMethod {
		GET,
		PUT,
		POST,
		HEAD,
		DELETE,
		OPTIONS,
		TRACE
	};
	
	private HTTPMethod method;
	private HashMap<String,Attribute> params;
	private String URL;
	private String urlNoQ;
	private boolean isForceAuth;
	private String authChainName;
	private List<NVP> queryStringParams;
	
	
	
	public RequestHolder(HTTPMethod method,HashMap<String,Attribute> params,String URL,String authChainName,List<NVP> queryStringParams) throws Exception {
		this.method = method;
		this.params = params;
		
		this.isForceAuth = false;
		this.authChainName = authChainName;
		this.setCorrectURL(URL);
		this.queryStringParams = queryStringParams;
		
	}
	
	public RequestHolder(HTTPMethod method,HashMap<String,Attribute> params,String URL,boolean isForceAuth,String authChainName,List<NVP> queryStringParams) throws Exception {
		this(method,params,URL,authChainName,queryStringParams);
		this.isForceAuth = isForceAuth;
	}
	
	public static HTTPMethod getMethod(String name) {
		if (name.equals("GET")) {
			return HTTPMethod.GET;
		} else if (name.equals("POST")) {
			return HTTPMethod.POST;
		} else if (name.equals("PUT")) {
			return HTTPMethod.PUT;
		} else if (name.equals("DELETE")) {
			return HTTPMethod.DELETE;
		} else if (name.equals("HEAD")) {
			return HTTPMethod.HEAD;
		} else if (name.equals("OPTIONS")) {
			return HTTPMethod.OPTIONS;
		} else if (name.equals("TRACE")) {
			return HTTPMethod.TRACE;
		} else {
			return null;
		}
	}

	public String getAuthChainName() {
		return authChainName;
	}

	public void setURL(String redirectToURL) {
		this.setCorrectURL(redirectToURL);
		
	}

	private void setCorrectURL(String url) {
		this.URL = url;
		this.urlNoQ = url;
		int qmark = this.urlNoQ.indexOf('?'); 
		if (qmark >= 0) {
			this.urlNoQ = this.urlNoQ.substring(0,qmark);
		}
	}
	
	public String getUrlNoQueryString() {
		return this.urlNoQ;
	}

	public List<NVP> getQueryStringParams() {
		return this.queryStringParams;
	}
}
