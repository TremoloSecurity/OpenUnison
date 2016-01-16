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


package com.tremolosecurity.server;

import java.util.HashMap;

import org.apache.log4j.Logger;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.proxy.util.ProxyConstants;

public class GlobalEntries {
	static Logger logger = Logger.getLogger(GlobalEntries.class.getName());
	
	static GlobalEntries ge = new GlobalEntries();
	
	HashMap<String,Object> vals;
	ConfigManager proxyConfigManager;
	
	public static GlobalEntries getGlobalEntries() {
		return ge;
	}
	
	public GlobalEntries() {
		if (logger.isDebugEnabled()) logger.debug("Creating new instance");
		this.vals = new HashMap<String,Object>();
	}
	
	public Object get(String name) {
		if (logger.isDebugEnabled()) logger.debug("Getting : '" + name + "' / '" + this.vals.get(name) + "'");
		return this.vals.get(name);
	}
	
	public void set(String name,Object obj) {
		if (logger.isDebugEnabled()) logger.debug("Setting : '" + name + "' / '" + obj + "'");
		this.vals.put(name, obj);
	}
	
	public ConfigManager getConfigManager() {
		return (ConfigManager) this.get(ProxyConstants.CONFIG_MANAGER);
	}
	
	public static void reset() {
		ge = new GlobalEntries();
	}
}
