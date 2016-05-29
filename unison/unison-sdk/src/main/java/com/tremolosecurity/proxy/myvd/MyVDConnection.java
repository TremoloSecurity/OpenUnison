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


package com.tremolosecurity.proxy.myvd;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.apache.logging.log4j.Logger;

import net.sourceforge.myvd.chain.BindInterceptorChain;
import net.sourceforge.myvd.chain.SearchInterceptorChain;
import net.sourceforge.myvd.chain.jdbcLdapImpl.EntrySetSearchResults;
import net.sourceforge.myvd.server.ServerCore;
import net.sourceforge.myvd.types.Bool;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Filter;
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.Results;
import net.sourceforge.myvd.types.SessionVariables;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPControl;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPExtendedOperation;
import com.novell.ldap.LDAPExtendedResponse;
import com.novell.ldap.LDAPMessage;
import com.novell.ldap.LDAPMessageQueue;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPResponseQueue;
import com.novell.ldap.LDAPSchema;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPSearchQueue;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.LDAPSocketFactory;
import com.novell.ldap.LDAPUnsolicitedNotificationListener;


/**
 * @author mlb
 *
 */
public class MyVDConnection  {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(MyVDConnection.class);
	
	ServerCore core;
	
	public MyVDConnection(ServerCore core) {
		this.core = core;
	}
	
	public LDAPSearchResults search(String base,int scope,String filter,ArrayList<String> attributes) throws LDAPException {
		HashMap<Object,Object> request = new HashMap<Object,Object>();
		HashMap<Object,Object> session = new HashMap<Object,Object>();
		
		session.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		session.put("MYVD_BINDDN",new DistinguishedName("cn=TremoloAdmin"));
		session.put("MYVD_BINDPASS",new Password());
		
		ArrayList<net.sourceforge.myvd.types.Attribute> lattribs = new ArrayList<net.sourceforge.myvd.types.Attribute>();
		Iterator<String> it = attributes.iterator();
		while (it.hasNext()) {
			lattribs.add(new net.sourceforge.myvd.types.Attribute(it.next()));
		}
		
		SearchInterceptorChain chain = new SearchInterceptorChain(new DistinguishedName("cn=TremoloAdmin"), new Password(), 0, core.getGlobalChain(),session,request,core.getRouter());
		
		DistinguishedName baseDN = new DistinguishedName(base);
		
		if (filter.contains("\\,")) {
			filter = filter.replaceAll("[\\\\][,]","\\\\5C,");		
		}

		Filter searchFilter = new Filter(filter);
		
		Results res = new Results(core.getGlobalChain(),0);
		
		chain.nextSearch(baseDN, new Int(scope), searchFilter, lattribs, new Bool(false), res, new LDAPSearchConstraints());
		
		return new EntrySetSearchResults(res);
	}
	
	public void bind(String dn,String password) throws LDAPException {
		HashMap<Object,Object> request = new HashMap<Object,Object>();
		HashMap<Object,Object> session = new HashMap<Object,Object>();
		
		session.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		session.put("MYVD_BINDDN",new DistinguishedName(""));
		session.put("MYVD_BINDPASS",new Password());
		
		BindInterceptorChain chain = new BindInterceptorChain(new DistinguishedName(""), new Password(), 0, core.getGlobalChain(),session,request,core.getRouter());
		
		
		chain.nextBind(new DistinguishedName(dn), new Password(password), new LDAPConstraints());
	}

}
