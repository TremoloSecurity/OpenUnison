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

import static org.apache.directory.ldap.client.api.search.FilterBuilder.equal;

import java.util.ArrayList;
import java.util.Iterator;

import com.tremolosecurity.proxy.TremoloHttpSession;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.AuthMechType;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.myvd.MyVDConnection;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;

public class LDAPBasicAuth implements BasicAuthImpl {
	public void doAuth(HttpServletRequest request,HttpSession session, String uidAttr,
			String userName, String password, MyVDConnection myvd,
			AuthChainType act, AuthMechType amt,AuthStep as,ConfigManager cfgMgr) throws LDAPException {
		
		String userDN = null;
		
		if (password == null || password.trim().length() == 0) {
			if (amt.getRequired().equals("required")) {
				as.setExecuted(true);
				as.setSuccess(false);
				
				return;
			}
		}
		
		
		
		LDAPSearchResults res = myvd.search(AuthUtil.getChainRoot(cfgMgr,act), 2, equal(uidAttr,userName).toString(), new ArrayList<String>());
		
		if (res.hasMore()) {
			LDAPEntry entry = res.next();
			while (res.hasMore()) res.next();
			
			userDN = entry.getDN();
			
			try {
				myvd.bind(entry.getDN(), password);
			} catch (LDAPException le) {
				request.setAttribute(ProxyConstants.AUTH_FAILED_USER_DN, userDN);
				throw le;
			}
			
			Iterator<LDAPAttribute> it = entry.getAttributeSet().iterator();
			AuthInfo authInfo = new AuthInfo(entry.getDN(),(String) session.getAttribute(ProxyConstants.AUTH_MECH_NAME),act.getName(),act.getLevel(),(TremoloHttpSession) session);
			
			AuthController actl = (AuthController) session.getAttribute(ProxyConstants.AUTH_CTL);
			if (actl == null) {
				actl = new AuthController();
				session.setAttribute(ProxyConstants.AUTH_CTL, actl);
			}
			
			actl.setAuthInfo(authInfo);
			
			while (it.hasNext()) {
				LDAPAttribute attrib = it.next();
				Attribute attr = new Attribute(attrib.getName());
				String[] vals = attrib.getStringValueArray();
				for (int i=0;i<vals.length;i++) {
					attr.getValues().add(vals[i]);
				}
				authInfo.getAttribs().put(attr.getName(), attr);
			}
			
			
			as.setExecuted(true);
			as.setSuccess(true);
			
			
			
			
		} else {
			
			request.setAttribute(ProxyConstants.AUTH_FAILED_USER_DN, userDN);
			
			as.setExecuted(true);
			as.setSuccess(false);
			 
		}
	}
}
