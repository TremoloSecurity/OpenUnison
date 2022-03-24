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
package com.tremolosecurity.scalejs.register.dynamicSource;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.graalvm.polyglot.Context;
import org.graalvm.polyglot.Value;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.scalejs.cfg.ScaleAttribute;
import com.tremolosecurity.scalejs.sdk.SourceList;
import com.tremolosecurity.util.NVP;

public class JavaScriptSource implements SourceList {

	static Logger logger = Logger.getLogger(JavaScriptSource.class);
	
	String javaScript;
	Map<String,Object> globals;
	boolean initCompleted;
	
	@Override
	public void init(ScaleAttribute attribute, Map<String, Attribute> config) {
		initCompleted = false;
		
		Context context = Context.newBuilder("js").allowAllAccess(true).build();
		globals = new HashMap<String,Object>();
		context.getBindings("js").putMember("globals", globals);
		
		
		
		try {
			Attribute attr = config.get("javaScript");
			if (attr == null) {
				logger.error("javaScript not set");
				return;
			}
		
			this.javaScript = attr.getValues().get(0);
			
			globals = new HashMap<String,Object>();
			context.getBindings("js").putMember("globals", globals);
			Value val = context.eval("js",this.javaScript);
			
			Value init = context.getBindings("js").getMember("init");
			if (init == null || ! init.canExecute()) {
				throw new ProvisioningException("initFilter function must be defined with two paramters");
			}
			
			Value getSourceList = context.getBindings("js").getMember("getSourceList");
			if (getSourceList == null || ! getSourceList.canExecute()) {
				throw new ProvisioningException("getSourceList function must be defined with one paramter");
			}
			
			
			Value validate = context.getBindings("js").getMember("validate");
			if (validate == null || ! validate.canExecute()) {
				throw new ProvisioningException("validate function must be defined with two paramters");
			}
			
			init.executeVoid(attribute, config);
			context.close();
			initCompleted = true;
		} catch (Throwable t) {
			logger.error("Could not initialize javascript filter",t);
			return;
		} finally {
			if (context != null) {
				context.close();
			}
		}

	}

	@Override
	public List<NVP> getSourceList(HttpFilterRequest request) throws Exception {
		if (this.initCompleted) {
			Context context = null;
			try {
				
				context = Context.newBuilder("js").allowAllAccess(true).build();
				context.getBindings("js").putMember("globals", globals);
				
				Value val = context.eval("js",this.javaScript);
				
				Value getSourceList = context.getBindings("js").getMember("getSourceList");
				
				Value resp = getSourceList.execute(request);
				if (resp != null) {
					List respValue = resp.as(List.class); 
					return respValue;
				} else {
					return null;
				}
				
			} finally {
				if (context != null) {
					context.close();
				}
			}
		} else {
			throw new Exception("javascript not initialized");
			
			
		}
	}

	@Override
	public String validate(String value, HttpFilterRequest request) throws Exception {
		if (this.initCompleted) {
			Context context = null;
			try {
				
				context = Context.newBuilder("js").allowAllAccess(true).build();
				context.getBindings("js").putMember("globals", globals);
				
				Value val = context.eval("js",this.javaScript);
				
				Value validate = context.getBindings("js").getMember("validate");
				
				Value resp = validate.execute(value,request);
				if (resp != null) {
					String respValue =  resp.asString();
					return respValue;
				} else {
					return null;
				}
				
			} finally {
				if (context != null) {
					context.close();
				}
			}
		} else {
			throw new Exception("javascript not initialized");
			
			
		}
	}

}
