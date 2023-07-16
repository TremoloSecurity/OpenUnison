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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import com.novell.ldap.LDAPException;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.AuthMechType;
import com.tremolosecurity.proxy.myvd.MyVDConnection;

public interface BasicAuthImpl {

	public void doAuth(HttpServletRequest request,HttpSession session, String uidAttr,
			String userName, String password, MyVDConnection myvd,
			AuthChainType act, AuthMechType amt,AuthStep as,ConfigManager cfgMgr) throws LDAPException;
}
