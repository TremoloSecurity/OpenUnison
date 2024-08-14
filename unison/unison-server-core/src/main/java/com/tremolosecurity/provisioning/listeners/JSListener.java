/*******************************************************************************
 * Copyright 2023 Tremolo Security, Inc.
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

package com.tremolosecurity.provisioning.listeners;

import java.util.HashMap;

import jakarta.jms.Message;

import org.apache.log4j.Logger;
import org.graalvm.polyglot.Context;
import org.graalvm.polyglot.Value;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.UnisonMessageListener;
import com.tremolosecurity.saml.Attribute;

public class JSListener extends UnisonMessageListener {
	static Logger logger = Logger.getLogger(JSListener.class);
	String js;

	boolean initCompleted;
	
	@Override
	public void onMessage(ConfigManager cfg, Object payload, Message msg) throws ProvisioningException {
		Context context = null;
		if (initCompleted) {
			try {
			context = Context.newBuilder("js").allowAllAccess(true).build();
			
			Value val = context.eval("js",this.js);
			
			Value onMessage = context.getBindings("js").getMember("onMessage");
			
			if (onMessage == null || ! onMessage.canExecute()) {
				throw new ProvisioningException("onMessage void function must be defined with three parameters");
			}
			
		
			onMessage.executeVoid(cfg,payload,msg);
			} finally {
				if (context != null) {
					context.close(true);
				}
			}
			
		} else {
			throw new ProvisioningException("Listener not initialized");
		}

	}

	@Override
	public void init(ConfigManager cfg, HashMap<String, Attribute> attributes) throws ProvisioningException {
		initCompleted = false;
		
		Context context = Context.newBuilder("js").allowAllAccess(true).build();
		
		Attribute attr = attributes.get("javaScript");
		if (attr == null) {
			logger.error("javaScript required");
			return;
		}
		
		this.js = attr.getValues().get(0);
		
		
		
		try {
			Value val = context.eval("js",this.js);
			
			Value onMessage = context.getBindings("js").getMember("onMessage");
			
			if (onMessage == null || ! onMessage.canExecute()) {
				throw new ProvisioningException("onMessage void function must be defined with three parameters");
			}
			
			this.initCompleted = true;
		} catch (Throwable t) {
			logger.error("Could not initialize js",t);
		}
		

	}

}
