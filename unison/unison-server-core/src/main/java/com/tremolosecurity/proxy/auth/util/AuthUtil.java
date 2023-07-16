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


package com.tremolosecurity.proxy.auth.util;

import jakarta.servlet.http.HttpSession;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.proxy.auth.AnonAuth;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.server.GlobalEntries;

public class AuthUtil {

	public static String getChainRoot(ConfigManager cfg,AuthChainType act) {
		String root = act.getRoot();
		if (root == null || root.trim().isEmpty()) {
			root = cfg.getCfg().getLdapRoot();
		}
		
		return root;
	}
	
	

}
