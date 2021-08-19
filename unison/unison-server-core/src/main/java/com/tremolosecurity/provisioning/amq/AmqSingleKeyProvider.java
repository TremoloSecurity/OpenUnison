/*******************************************************************************
 * Copyright 2021 Tremolo Security, Inc.
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
package com.tremolosecurity.provisioning.amq;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.jms.JMSContext;
import javax.jms.JMSException;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

import org.apache.activemq.transport.Transport;
import org.apache.log4j.Logger;

import com.tremolosecurity.server.GlobalEntries;



public  class AmqSingleKeyProvider extends org.apache.activemq.ActiveMQSslConnectionFactory {
	
	static Logger logger = Logger.getLogger(AmqSingleKeyProvider.class);

	String keyAlias;
	String trustAlias;
	
	
	
	
	
	public String getKeyAlias() {
		return keyAlias;
	}
	public void setKeyAlias(String keyAlias) {
		this.keyAlias = keyAlias;
	}
	public String getTrustAlias() {
		return trustAlias;
	}
	public void setTrustAlias(String trustAlias) {
		this.trustAlias = trustAlias;
	}
	
	
	@Override
	protected Transport createTransport() throws JMSException {
		KeyStore ks = null;
		try {
			ks = KeyStore.getInstance("PKCS12");
			ks.load(null, GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getKeyStorePassword().toCharArray());
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			logger.error("Could not initialize keystore",e);
			return null;
		}
		
		try {
			ks.setCertificateEntry(this.trustAlias,GlobalEntries.getGlobalEntries().getConfigManager().getCertificate(this.trustAlias));
		} catch (KeyStoreException e) {
			logger.error("Could not add certificate to keystore",e);
			return null;
		}
		
		try {
			ks.setKeyEntry(this.keyAlias, GlobalEntries.getGlobalEntries().getConfigManager().getPrivateKey(this.keyAlias),GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getKeyStorePassword().toCharArray(), new java.security.cert.X509Certificate[] {GlobalEntries.getGlobalEntries().getConfigManager().getCertificate(this.keyAlias)});
		} catch (KeyStoreException e) {
			logger.error("Could not add certificate to keystore",e);
			return null;
		}
		
		KeyManagerFactory kmf;
		try {
			kmf = KeyManagerFactory.getInstance("PKCS12");
			kmf.init(ks, GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getKeyStorePassword().toCharArray());
			super.keyManager = kmf.getKeyManagers();
		} catch (NoSuchAlgorithmException | UnrecoverableKeyException | KeyStoreException e) {
			logger.error("Could not initialize keystore",e);
			return null;
		}
		
		try {
			TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKCS12");
			tmf.init(ks);
			super.trustManager = tmf.getTrustManagers();
		} catch (NoSuchAlgorithmException  | KeyStoreException e) {
			logger.error("Could not initialize truststore",e);
			return null;
		}
		
		super.setTrustStoreType("PKCS12");
		super.setTrustStorePassword(GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getKeyStorePassword());
		
		super.setKeyStoreType("PKCS12");
		super.setKeyStorePassword(GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getKeyStorePassword());
		
		return super.createTransport();
	}
	
	
	

}
