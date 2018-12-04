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


package com.tremolosecurity.proxy.auth.ssl;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.HashMap;

import org.apache.logging.log4j.Logger;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.LDAPUrl;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.saml.Attribute;

public class LdapCRL implements CRLManager {
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(LdapCRL.class.getName());
	
	String host;
	int port;
	String base;
	String attribute;
	
	X509CRL crl;
	
	
	@Override
	public void init(String name, HashMap<String, Attribute> init,ConfigManager mgr) throws Exception {
		String url = init.get("crl." + name + ".path").getValues().get(0);
		
		LDAPUrl ldapUrl = new LDAPUrl(url);
		this.host = ldapUrl.getHost();
		this.port = ldapUrl.getPort();
		this.base = ldapUrl.getDN();
		this.attribute = "certificateRevocationList;binary";
		
		this.crl = getCRLFromLDAP();
		
		

	}

	private X509CRL getCRLFromLDAP() throws LDAPException, CertificateException,
			CRLException, IOException {
		LDAPConnection con = new LDAPConnection();
		con.connect(host, port);
		LDAPSearchResults res = con.search(this.base, 0, "(objectClass=*)", new String[] {this.attribute}, false);
		res.hasMore();
		LDAPEntry entry = res.next();
		byte[] crlBytes = entry.getAttribute(this.attribute).getByteValue();
		
		
		
		InputStream is = new ByteArrayInputStream(crlBytes);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		X509CRL crl = (X509CRL)cf.generateCRL(is);
		is.close();
		
		return crl;
	}

	@Override
	public boolean isValid(X509Certificate cert,X509Certificate issuer) {
		return ! this.crl.isRevoked(cert);
	}

	@Override
	public void validate() {
		try {
			X509CRL lcrl = this.getCRLFromLDAP();
			if (this.crl.getVersion() < lcrl.getVersion()) {
				logger.info("Updating CRL from LDAP");
				synchronized (this) {
					this.crl = lcrl;
				}
			} else {
				logger.info("CRL hasn't changed");
			}
		} catch (Exception e) {
			logger.error("Could not get CRL",e);
		} 
		

	}

}
