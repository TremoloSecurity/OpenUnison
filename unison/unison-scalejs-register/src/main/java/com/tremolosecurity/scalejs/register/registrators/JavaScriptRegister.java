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
package com.tremolosecurity.scalejs.register.registrators;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.graalvm.polyglot.Context;
import org.graalvm.polyglot.Value;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.scalejs.register.cfg.ScaleJSRegisterConfig;
import com.tremolosecurity.scalejs.register.data.NewUserRequest;
import com.tremolosecurity.scalejs.register.sdk.CreateRegisterUser;

public class JavaScriptRegister implements CreateRegisterUser {
	static Logger logger = Logger.getLogger(JavaScriptRegister.class);
	
	String javaScript;
	Map<String,Object> globals;
	boolean initCompleted;

	@Override
	public void init(ScaleJSRegisterConfig registerConfig) throws ProvisioningException {
		initCompleted = false;
		
		Context context = Context.newBuilder("js").allowAllAccess(true).build();
		globals = new HashMap<String,Object>();
		context.getBindings("js").putMember("globals", globals);
		
		
		
		try {
			Attribute attr = registerConfig.getCustomSubmissionConfig().get("javaScript");
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
			
			Value doFilter = context.getBindings("js").getMember("createTremoloUser");
			if (doFilter == null || ! doFilter.canExecute()) {
				throw new ProvisioningException("createTremoloUser function must be defined with three paramters");
			}
			
			init.executeVoid(registerConfig);
			
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
	public String createTremoloUser(NewUserRequest newUser, List<String> errors, AuthInfo userData)
			throws ProvisioningException {
		if (this.initCompleted) {
			Context context = Context.newBuilder("js").allowAllAccess(true).build();
			try {
				context.getBindings("js").putMember("globals", globals);
				
				context.getBindings("js").putMember("globals", globals);
				Value val = context.eval("js",this.javaScript);
				
				Value createTremoloUser = context.getBindings("js").getMember("createTremoloUser");
				Value result =  createTremoloUser.execute(newUser,errors,userData);
				
				
				
				if (result != null) {
					String restVal = result.asString();
					return restVal;
				} else {
					return null;
				}
			} finally {
				if (context != null) {
					context.close();
				}
			}
			
		} else {
			throw new ProvisioningException("javascript not initialized");
		}
		
		
	}

}
