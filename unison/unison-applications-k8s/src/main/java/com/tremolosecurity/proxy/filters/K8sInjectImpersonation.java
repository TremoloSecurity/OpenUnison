/*******************************************************************************
 * Copyright 2019 Tremolo Security, Inc.
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

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;

public class K8sInjectImpersonation implements HttpFilter {

	
	String userNameAttribute;
	String groupAttribute;
	boolean useLdapGroups;
	String targetName;
	
	
	@Override
	public void doFilter(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		Iterator<String> it = request.getHeaderNames();
		List<String> toRemove = new ArrayList<String>();
		while (it.hasNext()) {
			String headerName = it.next();
			if (headerName.toLowerCase().startsWith("impersonate-") || headerName.equalsIgnoreCase("Authorization")) {
				toRemove.add(headerName);
			}
		}
		
		for (String headerToRemove : toRemove) {
			request.removeHeader(headerToRemove);
		}
		
		request.removeHeader("Authorization");
		
		AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
		
		request.addHeader(new Attribute("Impersonate-User",userData.getAttribs().get(this.userNameAttribute).getValues().get(0)));
		
		Attribute groups = new Attribute("Impersonate-Group");
		groups.getValues().add("system:authenticated");
		Attribute fromUser = userData.getAttribs().get(this.groupAttribute);
		if (fromUser != null) {
			groups.getValues().addAll(fromUser.getValues());
			
		}
		
		if (groups.getValues().size() > 0) {
			
			
			
			request.addHeader(groups);
		}
		
		
		OpenShiftTarget target = (OpenShiftTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(this.targetName).getProvider();
		request.addHeader(new Attribute("Authorization",new StringBuilder().append("Bearer ").append(target.getAuthToken()).toString()));
		
		
		
		HashMap<String,String> uriParams = (HashMap<String,String>) request.getAttribute("TREMOLO_URI_PARAMS");
		uriParams.put("k8s_url", target.getUrl());
		
		
		chain.nextFilter(request, response, chain);
		
		
	}

	@Override
	public void filterResponseText(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain,
			StringBuffer data) throws Exception {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void filterResponseBinary(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain,
			byte[] data, int length) throws Exception {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void initFilter(HttpFilterConfig config) throws Exception {
		this.targetName = config.getAttribute("targetName").getValues().get(0);
		this.userNameAttribute = config.getAttribute("userNameAttribute").getValues().get(0);
		this.useLdapGroups = config.getAttribute("useLdapGroups").getValues().get(0).equalsIgnoreCase("true");
		if (! this.useLdapGroups) {
			this.groupAttribute = config.getAttribute("groupAttribute").getValues().get(0);
		}
		
	}

}
