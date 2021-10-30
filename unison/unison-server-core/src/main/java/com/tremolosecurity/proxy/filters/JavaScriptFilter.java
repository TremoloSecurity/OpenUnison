/*******************************************************************************
 * Copyright 2021 Tremolo Security, Inc.
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
package com.tremolosecurity.proxy.filters;

import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;
import org.graalvm.polyglot.Context;
import org.graalvm.polyglot.Value;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.saml.Attribute;

public class JavaScriptFilter implements HttpFilter {
	static Logger logger = Logger.getLogger(JavaScriptFilter.class);
	
	String javaScript;
	Map<String,Object> globals;
	boolean initCompleted;
	
	@Override
	public void doFilter(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		if (this.initCompleted) {
			Context context = Context.newBuilder("js").allowAllAccess(true).build();
			context.getBindings("js").putMember("globals", globals);
			
			context.getBindings("js").putMember("globals", globals);
			Value val = context.eval("js",this.javaScript);
			
			Value doFilter = context.getBindings("js").getMember("doFilter");
			doFilter.executeVoid(request,response,chain);
			
			context.close();
			
		} else {
			throw new Exception("javascript not initialized");
		}

	}

	@Override
	public void filterResponseText(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain,
			StringBuffer data) throws Exception {
		throw new Exception("not implemented");

	}

	@Override
	public void filterResponseBinary(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain,
			byte[] data, int length) throws Exception {
		throw new Exception("not implemented");

	}

	@Override
	public void initFilter(HttpFilterConfig config) throws Exception {
		initCompleted = false;
		
		Context context = Context.newBuilder("js").allowAllAccess(true).build();
		context.getBindings("js").putMember("globals", globals);
		
		
		
		try {
			Attribute attr = config.getAttribute("javaScript");
			if (attr == null) {
				logger.error("javaScript not set");
				return;
			}
		
			this.javaScript = attr.getValues().get(0);
			
			globals = new HashMap<String,Object>();
			context.getBindings("js").putMember("globals", globals);
			Value val = context.eval("js",this.javaScript);
			
			Value init = context.getBindings("js").getMember("initFilter");
			if (init == null || ! init.canExecute()) {
				throw new ProvisioningException("init function must be defined with one paramter");
			}
			
			Value doFilter = context.getBindings("js").getMember("doFilter");
			if (doFilter == null || ! doFilter.canExecute()) {
				throw new ProvisioningException("doFilter function must be defined with three paramters");
			}
			
			init.executeVoid(config);
			context.close();
			initCompleted = true;
		} catch (Throwable t) {
			logger.error("Could not initialize javascript filter",t);
			return;
		}
			

	}

}
