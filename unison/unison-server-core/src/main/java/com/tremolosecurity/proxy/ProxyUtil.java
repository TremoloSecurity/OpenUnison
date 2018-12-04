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


package com.tremolosecurity.proxy;

import java.util.Enumeration;
import java.util.HashMap;

import javax.servlet.http.HttpServletRequest;

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.saml.Attribute;

public class ProxyUtil {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(ProxyUtil.class);
	
	public static void loadParams(HttpServletRequest request,HashMap<String,Attribute> params) {
		Enumeration enumer = request.getParameterNames();
		while (enumer.hasMoreElements()) {
			String paramName = (String) enumer.nextElement();
			String[] vals = request.getParameterValues(paramName);
			
			if (vals != null) {
			Attribute attrib = new Attribute(paramName);
			params.put(attrib.getName(), attrib);
			for (int i=0;i<vals.length;i++) {
				attrib.getValues().add(vals[i]);
			}
			
			if (logger.isDebugEnabled()) {
				logger.debug("param '" + attrib.getName() + "' / '" + attrib.getValues() + "'");
			}
			}
			
			
			
		}
	}
}
