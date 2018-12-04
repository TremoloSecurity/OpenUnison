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


package com.tremolosecurity.proxy.ssl;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.server.GlobalEntries;

import net.sourceforge.myvd.inserts.ldap.LDAPSocketFactory;

public class TremoloSSLSocketFactory implements LDAPSocketFactory {

	
	SSLSocketFactory factory;
	
	public TremoloSSLSocketFactory() throws Exception {
		//mgr = TremoloContext.getContext().getRegistry("proxy").getCfgManager();
		ConfigManager cfgMgr = GlobalEntries.getGlobalEntries().getConfigManager();
		SSLContext sc = SSLContext.getInstance("TLS");
		//sc.init(null,new TrustManager[] { new TremoloTrustManager(mgr)}, null);
		sc.init(null,new TrustManager[] { new TremoloTrustManager(cfgMgr)}, null);
		factory = sc.getSocketFactory();
	}
	
	@Override
	public SSLSocketFactory getSSLSocketFactory() {
		 return factory;
	}

}
