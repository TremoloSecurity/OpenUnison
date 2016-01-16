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


package com.tremolosecurity.config.ssl;

import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;

import org.apache.log4j.Logger;

public class TremoloX509KeyManager extends X509ExtendedKeyManager  {
	static Logger logger = Logger.getLogger(TremoloX509KeyManager.class.getName());
	X509ExtendedKeyManager keyMgr;
	
	HashMap<String,X509Certificate[]> chains; 
	
	public TremoloX509KeyManager(X509ExtendedKeyManager keyMgr,KeyStore ks) {
		this.keyMgr = keyMgr;
		
		
		this.chains = new HashMap<String,X509Certificate[]>();
		try {
			Enumeration enumer = ks.aliases();
			while (enumer.hasMoreElements()) {
				String certName = (String) enumer.nextElement();
				X509Certificate cert = (X509Certificate) ks.getCertificate(certName);
				if (cert == null) {
					continue;
				}
				ArrayList<X509Certificate> chain = new ArrayList<X509Certificate>();
				chain.add(cert);
				addSigners(cert,chain,ks);
				
				X509Certificate[] certChain = new X509Certificate[chain.size()];
				for (int i=0;i<certChain.length;i++) {
					certChain[i] = chain.get(i);
				}
				
				this.chains.put(certName, certChain);
			}
		} catch (KeyStoreException e) {
			logger.error("Could not generate certificate chains",e);
		}
		
	}
	
	private void addSigners(X509Certificate cert,
			ArrayList<X509Certificate> chain,KeyStore ks) throws KeyStoreException {
		Principal signer = cert.getIssuerX500Principal();
		Enumeration enumer = ks.aliases();
		while (enumer.hasMoreElements()) {
			String alias = (String) enumer.nextElement();
			X509Certificate curCert = (X509Certificate) ks.getCertificate(alias);
			if (curCert == null) {
				continue;
			}
			
			if (curCert.equals(cert)) {
				continue;
			} else if (curCert.getSubjectX500Principal().equals(signer)) {
				chain.add(curCert);
				if (! curCert.getIssuerX500Principal().equals(curCert.getSubjectX500Principal())) {
					this.addSigners(curCert, chain, ks);
				}
			}
		}
		
	}

	@Override
	public String chooseEngineClientAlias(String[] arg0, Principal[] arg1,
			SSLEngine arg2) {
		String alias = keyMgr.chooseEngineClientAlias(arg0, arg1, arg2); 
		if (logger.isDebugEnabled()) {
			logger.debug("in choose client engine : " + alias);
		}
		return alias;
	}

	@Override
	public String chooseEngineServerAlias(String arg0, Principal[] arg1,
			SSLEngine arg2) {
		return keyMgr.chooseEngineServerAlias(arg0, arg1, arg2);
		//return alias;
	}

	@Override
	public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
		return this.keyMgr.chooseClientAlias(keyType, issuers, socket);
	}

	@Override
	public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
		//return this.alias;
		return this.keyMgr.chooseServerAlias(keyType, issuers, socket);
	}

	@Override
	public X509Certificate[] getCertificateChain(String alias) {
		if (logger.isDebugEnabled()) {
			logger.debug("getting chain for : " + alias);
		}
		X509Certificate[] chain = this.chains.get(alias);
		return chain;
	}

	@Override
	public String[] getClientAliases(String keyType, Principal[] issuers) {
		return this.keyMgr.getClientAliases(keyType, issuers);
	}

	@Override
	public PrivateKey getPrivateKey(String alias) {
		return this.keyMgr.getPrivateKey(alias);
	}

	@Override
	public String[] getServerAliases(String keyType, Principal[] issuers) {
		return this.keyMgr.getServerAliases(keyType, issuers);
	}

}
