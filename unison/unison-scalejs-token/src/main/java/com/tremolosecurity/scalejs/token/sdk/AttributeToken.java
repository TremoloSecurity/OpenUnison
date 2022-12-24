/*******************************************************************************
 * Copyright 2016 Tremolo Security, Inc.
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
package com.tremolosecurity.scalejs.token.sdk;

import java.util.ArrayList;
import java.util.HashMap;

import javax.servlet.http.HttpSession;

import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.saml.Attribute;
import javax.servlet.http.HttpServletRequest;;


public class AttributeToken implements TokenLoader {

	ArrayList<String> attributes;
	
	@Override
	public void init(HttpFilterConfig config,com.tremolosecurity.scalejs.token.cfg.ScaleTokenConfig scaleTokenConfig) throws Exception {
		this.attributes = new ArrayList<String>();
		this.attributes.addAll(config.getAttribute("attributes").getValues());

	}

	@Override
	public Object loadToken(AuthInfo user, HttpSession session,HttpServletRequest request) throws Exception {
		HashMap<String,String> attrs = new HashMap<String,String>();
		
		for (String attrName : this.attributes) {
			Attribute attr = user.getAttribs().get(attrName);
			if (attr != null) {
				attrs.put(attr.getName(),attr.getValues().get(0));
			}
		}
		
		return attrs;
	}



}
