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
package com.tremolosecurity.openunison.myvd;

import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509ExtendedKeyManager;

import org.apache.directory.server.ldap.LdapServerImpl;

import com.tremolosecurity.config.ssl.AliasX509KeyManager;

public class MyVDOpenUnisonLDAPServer extends LdapServerImpl {
	X509ExtendedKeyManager keyManager;
	KeyStore ks;
	String keyAlias;

	@Override
	public void loadKeyStore() throws Exception {
		//do nothing
	}
	
	@Override
	public SSLContext getSSLContext() throws NoSuchAlgorithmException, KeyManagementException {
		
		if (this.keyAlias != null) {
			SSLContext sslc = SSLContext.getInstance("TLS");
			
			X509ExtendedKeyManager keyMgr = (X509ExtendedKeyManager) keyManager;
			KeyManager[] keyManagers = new KeyManager[1];
			keyManagers[0] = new AliasX509KeyManager(keyAlias,keyMgr,ks);
			
			sslc.init(keyManagers, null, null);
			
			return sslc;
		} else {
			return super.getSSLContext();
		}
	}
	
	public void setTlsParams(String keyAlias,KeyStore ks,X509ExtendedKeyManager keyManager) {
		this.keyAlias = keyAlias;
		this.ks = ks;
		this.keyManager = keyManager;
	}
}
