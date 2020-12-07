/*
Copyright 2015, 2016 Tremolo Security, Inc.

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


package com.tremolosecurity.proxy.filter;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;

import javax.servlet.ServletContext;

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.FilterConfigType;
import com.tremolosecurity.config.xml.ParamType;
import com.tremolosecurity.config.xml.ParamWithValueType;
import com.tremolosecurity.proxy.TremoloHttpSession;
import com.tremolosecurity.saml.*;

public class HttpFilterConfig {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(HttpFilterConfig.class);
	
	ConfigManager cfgMgr;
	FilterConfigType cfg;
	HashMap<String,Attribute> params;
	
	public HttpFilterConfig(FilterConfigType cfg,ConfigManager cfgMgr) {
		this.cfg = cfg;
		this.params = new HashMap<String,Attribute>();
		this.cfgMgr = cfgMgr;
		
		Iterator<ParamWithValueType> params = cfg.getParam().iterator();
		while (params.hasNext()) {
			ParamWithValueType param = params.next();
			Attribute lparam = this.params.get(param.getName());
			if (lparam == null) {
				lparam = new Attribute(param.getName());
				this.params.put(param.getName(), lparam);
			}
			
			
			if (param.getValueAttribute() != null) {
				lparam.getValues().add(param.getValueAttribute());
			} else {
				lparam.getValues().add(param.getValue());
			}
			
			
		}
	}
	
	public ConfigManager getConfigManager() {
		return cfgMgr;
	}

	public Attribute getAttribute(String name) {
		return this.params.get(name);
	}
	
	public Set<String> getAttributeNames() {
		return params.keySet();
	}
}
