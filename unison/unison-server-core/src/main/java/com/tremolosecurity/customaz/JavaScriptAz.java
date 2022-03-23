/*
Copyright 2022 Tremolo Security, Inc.

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

package com.tremolosecurity.customaz;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.graalvm.polyglot.Context;
import org.graalvm.polyglot.Value;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.az.AzException;
import com.tremolosecurity.proxy.az.CustomAuthorization;
import com.tremolosecurity.saml.Attribute;

public class JavaScriptAz implements CustomAuthorization {
	static Logger logger = Logger.getLogger(JavaScriptAz.class);
	
	HashMap<String,Object> globals;
	String javaScript;
	boolean initCompleted;

	@Override
	public void init(Map<String, Attribute> config) throws AzException {
		initCompleted = false;		
		Context context = Context.newBuilder("js").allowAllAccess(true).build();
		
		try {
			globals = new HashMap<String,Object>();
			context.getBindings("js").putMember("globals", globals);
		
		
		
		
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
				throw new ProvisioningException("init function must be defined with one paramter");
			}
			
			init.executeVoid(config);
			
			init = context.getBindings("js").getMember("isAuthorized");
			if (init == null || ! init.canExecute()) {
				throw new ProvisioningException("isAuthorized function must be defined with at least one paramter");
			}
			
			init = context.getBindings("js").getMember("listPossibleApprovers");
			if (init == null || ! init.canExecute()) {
				throw new ProvisioningException("listPossibleApprovers function must be defined");
			}
			
			
			
			initCompleted = true;
		} catch (Throwable t) {
			logger.error("Could not initialize javascript filter",t);
			return;
		} finally {
			context.close();
		}
		
		

	}

	@Override
	public void loadConfigManager(ConfigManager cfg) throws AzException {
		globals.put("az.configmanager", cfg);

	}

	@Override
	public void setWorkflow(Workflow wf) throws AzException {
		globals.put("az.workflow", wf);

	}

	@Override
	public boolean isAuthorized(AuthInfo subject, String... params) throws AzException {
		if (this.initCompleted) {
			Context context = Context.newBuilder("js").allowAllAccess(true).build();
			try {
				context.getBindings("js").putMember("globals", globals);
				
				context.getBindings("js").putMember("globals", globals);
				Value val = context.eval("js",this.javaScript);
				
				Value isAuthorized = context.getBindings("js").getMember("isAuthorized");
				Value result = isAuthorized.execute(subject,params);
				return result.asBoolean();
			} finally {
				context.close();
			}
			
		} else {
			throw new AzException("javascript not initialized");
		}
	}

	@Override
	public List<String> listPossibleApprovers(String... params) throws AzException {
		if (this.initCompleted) {
			Context context = Context.newBuilder("js").allowAllAccess(true).build();
			try {
				context.getBindings("js").putMember("globals", globals);
				
				context.getBindings("js").putMember("globals", globals);
				Value val = context.eval("js",this.javaScript);
				
				Value listPossibleApprovers = context.getBindings("js").getMember("listPossibleApprovers");
				Value result = listPossibleApprovers.execute(params);
				return result.as(List.class);
			} finally {
				context.close();
			}
			
		} else {
			throw new AzException("javascript not initialized");
		}
	}

	@Override
	public Workflow getWorkflow() {
		return (Workflow) globals.get("az.workflow");
	}

}
