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
import java.util.ArrayList;

import org.apache.logging.log4j.Logger;

import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPJSSESecureSocketFactory;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;



public class LdapPool {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(LdapPool.class);
	
	ArrayList<LdapConnection> cons;
	private String host;
	private int port;
	private String bindDN;
	private String password;
	private boolean isSSL;
	private int minNum;
	private int maxNum;
	private long idleTimeout;
	private ConfigManager cfgMgr;
	private boolean useSRV;
	
	public LdapPool(ConfigManager cfgMgr,String host, int port, String bindDN, String password, boolean isSSL,int minNum,int maxNum,long idleTimeout, boolean useSRV) throws ProvisioningException {
		this.host = host;
		this.port = port;
		this.bindDN = bindDN;
		this.password = password;
		this.isSSL = isSSL;
		
		this.minNum = minNum;
		this.maxNum = maxNum;
		
		this.useSRV = useSRV;
		
		this.cons = new ArrayList<LdapConnection>();
		this.cfgMgr = cfgMgr;
		
		for (int i=0;i<minNum;i++) {
			LdapConnection con = new LdapConnection(this.cfgMgr,this.host,this.port,this.bindDN,this.password,this.isSSL,this.idleTimeout,this.useSRV);
			con.connect();
			this.cons.add(con);
		}
		
		
	}
	
	public LdapConnection getConnection() throws ProvisioningException {
		return this.getConnection(0);
	}
	
	private LdapConnection getConnection(int num) throws ProvisioningException {
		if (num > 100) {
			throw new ProvisioningException("No connections available");
		}
		
		for (LdapConnection con : this.cons) {
			if (! con.isInUse()) {
				con.test();
				return con;
			}
		}
		
		
			if (cons.size() < this.maxNum) {
				LdapConnection con = new LdapConnection(this.cfgMgr,this.host,this.port,this.bindDN,this.password,this.isSSL,this.idleTimeout,this.useSRV);
				con.connect();
				con.isInUse();
				synchronized (this.cons) {
					cons.add(con);
				}
				return con;
			}
		
		
		try {
			Thread.sleep(1000);
		} catch (InterruptedException e) {
			//don't care
		}
		
		return this.getConnection(num+1);
	}
	
	public void shutdown() {
		for (LdapConnection con : this.cons) {
			try {
				con.getConnection().disconnect();
			} catch (LDAPException e) {
				logger.warn("Problem closing connection",e);
			}
		}
	}
	
	
}

