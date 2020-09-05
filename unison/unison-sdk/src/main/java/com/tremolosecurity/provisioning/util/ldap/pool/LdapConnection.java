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


package com.tremolosecurity.provisioning.util.ldap.pool;

import java.io.UnsupportedEncodingException;

import org.apache.logging.log4j.Logger;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPJSSESecureSocketFactory;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.proxy.ssl.TremoloSSLSocketFactory;

public class LdapConnection {
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(LdapConnection.class.getName());
	private boolean inUse;
	
	private String host;
	private int port;
	private String bindDN;
	private String password;
	private boolean isSSL;
	private long lastUsed;
	private long idelTime;
	
	
	private LDAPConnection con;
	private ConfigManager cfgMgr;
	
	public LdapConnection(ConfigManager cfgMgr,String host, int port, String bindDN, String password, boolean isSSL,long idleTime) {
		this.host = host;
		this.port = port;
		this.bindDN = bindDN;
		this.password = password;
		this.isSSL = isSSL;
		this.inUse = false;
		this.lastUsed = System.currentTimeMillis();
		this.idelTime = idleTime;
		this.cfgMgr = cfgMgr;
	}
	
	public void connect()  throws ProvisioningException {
		this.connect(0);
	}
	
	private void connect(int num) throws ProvisioningException {
		if (num > 5) {
			throw new ProvisioningException("Too many attempts to connect to " + this.host + " on port " + this.port);
		}
		
		if (con != null) {
			
			final LDAPConnection localCon = con;
			
			new Thread() {
				public void run() {
					try {
						
						localCon.disconnect();
						
					} catch (LDAPException e) {
						logger.warn("Could not close the connection",e);
					}
				}
			}.start();
			
			
		}
		
		
		if (this.isSSL) {
			try {
				this.con = new LDAPConnection(new LDAPJSSESecureSocketFactory((new TremoloSSLSocketFactory()).getSSLSocketFactory()));
				//this.con.setSocketTimeOut(5);
			} catch (Exception e) {
				logger.error("Could not connect",e);
			}
		} else {
			this.con = new LDAPConnection();
			//this.con.setSocketTimeOut(5);
		}
		
		
		try {
			this.con.connect(host, port);
			this.con.bind(3,bindDN,password.getBytes("UTF-8"));
		} catch (UnsupportedEncodingException e) {
			logger.error("Could not bind",e);
			this.connect(num + 1);
		} catch (LDAPException e) {
			logger.error("Could not bind",e);
			this.connect(num + 1);
		}
	}
	
	public void test() throws ProvisioningException {
		
		if (logger.isDebugEnabled()) {
			logger.debug("Current Time - " + System.currentTimeMillis());
			logger.debug("Last Used Time - " + this.lastUsed);
			logger.debug("Difference - " + (System.currentTimeMillis() - this.lastUsed));
			logger.debug("Create new connection : " + ((System.currentTimeMillis() - this.lastUsed) >= this.idelTime));
		}
		
		if ((System.currentTimeMillis() - this.lastUsed) >= this.idelTime ) {
			if (logger.isDebugEnabled()) {
				logger.debug("Creating new connection");
			}
			this.connect();
			return;
		}
		
		try {
			LDAPSearchResults res = this.con.search("", 0, "(objectClass=*)", new String[] {"1.1"}, false);
			if (res.hasMore()) {
				LDAPEntry entry = res.next();
				entry.getDN();
			}
			
		} catch (Throwable t) {
			logger.warn("Connection died",t);
			this.connect();
		}
	}

	public synchronized boolean isInUse() {
		if (this.inUse) {
			return true;
		} else {
			inUse = true;
			return false;
		}
		
	}

	public synchronized void returnCon() {
		this.inUse = false;
		this.lastUsed = System.currentTimeMillis();
	}

	public LDAPConnection getConnection() {
		return this.con;
		
	}
	
	
}

