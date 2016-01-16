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


package com.tremolosecurity.proxy.auth.ssl;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.HashMap;

import org.apache.log4j.Logger;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.saml.Attribute;

public class FileCRL implements CRLManager {
	static Logger logger = Logger.getLogger(FileCRL.class.getName());
	String path;
	X509CRL crl;
	long lastModified;
	
	@Override
	public void init(String name, HashMap<String, Attribute> init,ConfigManager mgr) throws Exception {
		this.path = init.get("crl." + name + ".path").getValues().get(0);
		String CRL_PATH = System.getenv("TREMOLO_CRLS");
		this.path = CRL_PATH + "/" + this.path;
	
		InputStream is = new FileInputStream(this.path);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		crl = (X509CRL)cf.generateCRL(is);
		is.close();
		
		File f = new File(path);
		this.lastModified = f.lastModified();

	}

	@Override
	public boolean isValid(X509Certificate cert,X509Certificate issuer) {
		
		return ! this.crl.isRevoked(cert);
	}

	@Override
	public void validate() {
		File f = new File(path);
		if (f.lastModified() > this.lastModified) {
			logger.info("CRL " + this.path + " has been updated");
			synchronized (this) {
				try {
					InputStream is = new FileInputStream(f);
					CertificateFactory cf = CertificateFactory.getInstance("X.509");
					crl = (X509CRL)cf.generateCRL(is);
					is.close();
					this.lastModified = f.lastModified();
				} catch (Exception e) {
					logger.error("unable to load crl",e);
				}
			}
		} else {
			logger.info("CRL not changed");
		}

	}

}
